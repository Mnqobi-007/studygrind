from flask import Flask, render_template, send_from_directory, redirect, url_for, jsonify
from flask_login import LoginManager, login_required, current_user
from flask_migrate import Migrate
from config import config
from models import db, User
from auth import auth_bp, init_oauth
from api import api_bp
import os
import sys

# Determine environment
env = os.environ.get('FLASK_ENV', 'development')
app = Flask(__name__)
app.config.from_object(config[env])

# Add session security settings
IS_PRODUCTION = app.config.get('IS_PRODUCTION', False)
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize OAuth
init_oauth(app)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')

# Create upload folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== FILE SERVING ROUTES ====================
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    """Serve files from uploads folder"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== PAGE ROUTES ====================
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_teacher():
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('login.html')

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if not current_user.is_student():
        return redirect(url_for('index'))
    return render_template('student_dashboard.html', user=current_user)

@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if not current_user.is_teacher():
        return redirect(url_for('index'))
    return render_template('teacher_dashboard.html', user=current_user)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html', user=current_user)

# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'database': str(db.engine.url).split('@')[0] + '@***' if db.engine.url else 'unknown',
        'environment': 'production' if IS_PRODUCTION else 'development'
    })

# Initialize database
def init_db():
    with app.app_context():
        try:
            # Create tables
            db.create_all()
            print("✅ Database tables created/verified")
            
            # Only create sample data in development
            if not IS_PRODUCTION:
                if not User.query.filter_by(role='admin').first():
                    admin = User(
                        username='admin',
                        email='admin@studygrind.com',
                        role='admin',
                        full_name='System Administrator'
                    )
                    admin.set_password('admin123')
                    db.session.add(admin)
                    
                    teacher = User(
                        username='prof_harrison',
                        email='harrison@studygrind.com',
                        role='teacher',
                        full_name='Prof. Harrison'
                    )
                    teacher.set_password('teacher123')
                    db.session.add(teacher)
                    
                    student = User(
                        username='alex_smith',
                        email='alex@studygrind.com',
                        role='student',
                        full_name='Alex Smith'
                    )
                    student.set_password('student123')
                    db.session.add(student)
                    
                    db.session.commit()
                    print("=" * 50)
                    print("📝 Sample users created for development")
                    print("=" * 50)
                    print("Admin:    admin@studygrind.com / admin123")
                    print("Teacher:  harrison@studygrind.com / teacher123")
                    print("Student:  alex@studygrind.com / student123")
                    print("=" * 50)
            else:
                print("🌐 Production environment - no sample data created")
                
        except Exception as e:
            print(f"⚠️ Database initialization error: {e}")

# Initialize database
init_db()

# For gunicorn (Render)
app = app
