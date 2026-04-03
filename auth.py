from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from werkzeug.security import generate_password_hash
from authlib.integrations.flask_client import OAuth
import os
import secrets
import requests

auth_bp = Blueprint('auth', __name__)

# Initialize OAuth
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    
    # Google OAuth only
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
            oauth.register(
                name='google',
                client_id=app.config['GOOGLE_CLIENT_ID'],
                client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={'scope': 'openid email profile'},
                authorize_params={'access_type': 'offline', 'prompt': 'select_account'}
            )
            print("✓ Google OAuth configured successfully")
        else:
            print("✗ Google OAuth credentials found but empty")
    else:
        print("ℹ Google OAuth not configured - email login works fine")

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        login_user(user, remember=data.get('remember_me', False))
        
        if user.is_admin():
            return jsonify({'success': True, 'redirect': '/admin/dashboard'})
        elif user.is_teacher():
            return jsonify({'success': True, 'redirect': '/teacher/dashboard'})
        else:
            return jsonify({'success': True, 'redirect': '/student/dashboard'})
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'success': False, 'error': 'Email already registered'}), 400
    
    user = User(
        username=data.get('username', data.get('email').split('@')[0]),
        email=data.get('email'),
        role='student',
        full_name=data.get('full_name')
    )
    user.set_password(data.get('password'))
    
    db.session.add(user)
    db.session.commit()
    
    login_user(user)
    return jsonify({'success': True, 'redirect': '/student/dashboard'})

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/current_user')
@login_required
def current_user_info():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role,
        'full_name': current_user.full_name
    })

# ==================== Google OAuth Routes ====================

@auth_bp.route('/login/google')
def google_login():
    if not oauth._clients.get('google'):
        flash('Google OAuth not configured', 'error')
        return redirect(url_for('auth.login'))
    
    # Store the next URL in session if provided
    next_url = request.args.get('next')
    if next_url:
        session['oauth_next'] = next_url
    
    redirect_uri = url_for('auth.google_callback', _external=True)
    print(f"Google OAuth redirect URI: {redirect_uri}")
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/login/google/callback')
def google_callback():
    try:
        # Get the token
        token = oauth.google.authorize_access_token()
        print(f"✓ Token received")
        
        # Get user info using the token directly
        userinfo_endpoint = 'https://www.googleapis.com/oauth2/v3/userinfo'
        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        response = requests.get(userinfo_endpoint, headers=headers)
        
        if response.status_code != 200:
            print(f"✗ Failed to get user info: {response.status_code}")
            flash('Failed to get user information from Google', 'error')
            return redirect(url_for('auth.login'))
        
        user_info = response.json()
        print(f"✓ User info received: {user_info.get('email')}")
        
        email = user_info.get('email')
        name = user_info.get('name', email.split('@')[0])
        
        if not email:
            flash('Email not provided by Google', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create new user
            random_password = secrets.token_urlsafe(16)
            user = User(
                username=email.split('@')[0],
                email=email,
                role='student',
                full_name=name
            )
            user.set_password(random_password)
            db.session.add(user)
            db.session.commit()
            print(f"✓ Created new user: {email}")
        else:
            print(f"✓ Existing user logged in: {email}")
        
        # Log the user in
        login_user(user, remember=True)
        
        # Force session save
        session.modified = True
        
        print(f"✓ User logged in successfully: {user.email}, Role: {user.role}")
        
        # Redirect based on role
        next_url = session.pop('oauth_next', None)
        if next_url:
            return redirect(next_url)
        
        if user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif user.is_teacher():
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
            
    except Exception as e:
        print(f"✗ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        flash('Google login failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))