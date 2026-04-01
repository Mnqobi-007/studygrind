from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from werkzeug.security import generate_password_hash
from authlib.integrations.flask_client import OAuth
import os

auth_bp = Blueprint('auth', __name__)

# Initialize OAuth
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    
    # Google OAuth only
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'}
        )
        print("Google OAuth configured successfully")
    else:
        print("Google OAuth not configured - missing credentials")

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        login_user(user)
        
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
        return "Google OAuth not configured. Please add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env file", 400
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/login/google/callback')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        
        email = user_info.get('email')
        name = user_info.get('name', email.split('@')[0])
        
        if not email:
            return "Email not provided by Google", 400
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create new user
            import secrets
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
            print(f"Created new user via Google OAuth: {email}")
        
        login_user(user)
        
        if user.is_admin():
            return redirect('/admin/dashboard')
        elif user.is_teacher():
            return redirect('/teacher/dashboard')
        else:
            return redirect('/student/dashboard')
            
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return redirect('/auth/login')