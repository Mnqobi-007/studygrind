from flask import Flask, render_template, send_from_directory, redirect, url_for
from flask_login import LoginManager, login_required, current_user
from flask_migrate import Migrate
from config import Config
from models import db, User
from auth import auth_bp, init_oauth
from api import api_bp
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions FIRST
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Initialize OAuth
init_oauth(app)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')

# Create upload folders AFTER config is loaded
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/uploads', exist_ok=True)

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

# Create database and seed data
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@studygrind.com',
                role='admin',
                full_name='System Administrator'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
            # Create sample teacher
            teacher = User(
                username='prof_harrison',
                email='harrison@studygrind.com',
                role='teacher',
                full_name='Prof. Harrison'
            )
            teacher.set_password('teacher123')
            db.session.add(teacher)
            
            # Create sample student
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
            print("Database initialized with sample users!")
            print("=" * 50)
            print("Admin:    admin@studygrind.com / admin123")
            print("Teacher:  harrison@studygrind.com / teacher123")
            print("Student:  alex@studygrind.com / student123")
            print("=" * 50)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)