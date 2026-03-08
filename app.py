# app.py - StudyGrind Application (Render-Ready - FIXED VERSION)

import os
import math
import time
import secrets
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template, send_file, redirect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static',
            static_url_path='/static')

# Configuration - Use environment variables for production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'studygrind-secure-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///studygrind.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# File upload config - Use /tmp for ephemeral storage on Render
if os.environ.get('RENDER'):
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
else:
    app.config['UPLOAD_FOLDER'] = 'uploads'
    
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'csv', 'ppt', 'pptx', 'mp4', 'avi', 'mov'}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
CORS(app, supports_credentials=True)

# ========== DATABASE MODELS ==========

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None
        }

class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(100))
    tags = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    is_teacher_note = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref='notes')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'subject': self.subject,
            'tags': self.tags,
            'user_id': self.user_id,
            'user_name': self.user.name if self.user else '',
            'is_public': self.is_public,
            'is_teacher_note': self.is_teacher_note,
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'updated_at': self.updated_at.isoformat() + 'Z' if self.updated_at else None
        }

class Textbook(db.Model):
    __tablename__ = 'textbooks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200))
    description = db.Column(db.Text)
    subject = db.Column(db.String(100))
    filename = db.Column(db.String(300))
    file_size = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    downloads = db.Column(db.Integer, default=0)
    
    uploader = db.relationship('User', backref='textbooks')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'description': self.description,
            'subject': self.subject,
            'filename': self.filename,
            'file_size': self.file_size,
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.name if self.uploader else '',
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'downloads': self.downloads
        }

class Resource(db.Model):
    __tablename__ = 'resources'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    resource_type = db.Column(db.String(50))
    subject = db.Column(db.String(100))
    filename = db.Column(db.String(300))
    file_size = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    downloads = db.Column(db.Integer, default=0)
    
    uploader = db.relationship('User', backref='resources')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'resource_type': self.resource_type,
            'subject': self.subject,
            'filename': self.filename,
            'file_size': self.file_size,
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.name if self.uploader else '',
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'downloads': self.downloads
        }

class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    subject = db.Column(db.String(100))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='links')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'url': self.url,
            'description': self.description,
            'subject': self.subject,
            'created_by': self.created_by,
            'creator_name': self.creator.name if self.creator else '',
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None
        }

class Assignment(db.Model):
    __tablename__ = 'assignments'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    instructions = db.Column(db.Text)
    subject = db.Column(db.String(100))
    max_score = db.Column(db.Integer, default=100)
    due_date = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', backref='assignments')
    
    @property
    def serialize(self):
        now = datetime.utcnow()
        days_remaining = (self.due_date - now).days if self.due_date > now else 0
        submissions = Submission.query.filter_by(assignment_id=self.id).count()
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'instructions': self.instructions,
            'subject': self.subject,
            'max_score': self.max_score,
            'due_date': self.due_date.isoformat() + 'Z' if self.due_date else None,
            'created_by': self.created_by,
            'creator_name': self.creator.name if self.creator else '',
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'is_active': self.is_active,
            'days_remaining': days_remaining,
            'submissions': submissions
        }

class Submission(db.Model):
    __tablename__ = 'submissions'
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text)
    grade = db.Column(db.Float)
    feedback = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    graded_at = db.Column(db.DateTime)
    file_count = db.Column(db.Integer, default=0)
    
    assignment = db.relationship('Assignment', backref=db.backref('submissions', cascade='all, delete-orphan'))
    student = db.relationship('User', backref='submissions')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'assignment_id': self.assignment_id,
            'student_id': self.student_id,
            'student_name': self.student.name if self.student else '',
            'content': self.content,
            'grade': self.grade,
            'feedback': self.feedback,
            'submitted_at': self.submitted_at.isoformat() + 'Z' if self.submitted_at else None,
            'graded_at': self.graded_at.isoformat() + 'Z' if self.graded_at else None,
            'file_count': self.file_count,
            'assignment_title': self.assignment.title if self.assignment else ''
        }

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    event_type = db.Column(db.String(50), default='class')
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    all_day = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(200))
    color = db.Column(db.String(20), default='#2196f3')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='events')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'event_type': self.event_type,
            'start_date': self.start_date.isoformat() + 'Z' if self.start_date else None,
            'end_date': self.end_date.isoformat() + 'Z' if self.end_date else None,
            'all_day': self.all_day,
            'location': self.location,
            'color': self.color,
            'created_by': self.created_by,
            'creator_name': self.creator.name if self.creator else '',
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None
        }

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='notifications')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'type': self.type,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None
        }

# ========== HELPER FUNCTIONS ==========

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_file_size(bytes):
    if bytes == 0:
        return '0 Bytes'
    k = 1024
    sizes = ['Bytes', 'KB', 'MB', 'GB']
    i = int(math.floor(math.log(bytes) / math.log(k)))
    return f"{round(bytes / math.pow(k, i), 2)} {sizes[i]}"

def create_notification(user_id, type, title, message):
    """Create an in-app notification"""
    try:
        notification = Notification(
            user_id=user_id,
            type=type,
            title=title,
            message=message
        )
        db.session.add(notification)
        db.session.commit()
        return notification
    except Exception as e:
        print(f"Notification error: {e}")
        return None

def get_file_size(file):
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size

def save_uploaded_file(file, subdirectory):
    """Save uploaded file with security checks"""
    try:
        if not file or not file.filename:
            raise ValueError('No file provided')
        
        filename = secure_filename(file.filename)
        if not filename:
            raise ValueError('Invalid filename')
        
        # Check file size
        file_size = get_file_size(file)
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            raise ValueError('File too large')
        
        # Generate unique filename
        name, ext = os.path.splitext(filename)
        timestamp = int(time.time())
        unique_id = secrets.token_hex(4)
        unique_filename = f"{name}_{timestamp}_{unique_id}{ext}"
        
        # Save file
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], subdirectory)
        os.makedirs(upload_path, exist_ok=True)
        file_path = os.path.join(upload_path, unique_filename)
        file.save(file_path)
        
        return unique_filename, file_size
        
    except Exception as e:
        print(f'Failed to save file: {str(e)}')
        raise

# ========== USER LOADER ==========

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ========== DATABASE INITIALIZATION ==========

def init_db():
    """Initialize database with sample data only if empty"""
    try:
        db.create_all()
        print("✅ Database tables created/verified")
        
        # Only create default users if NO users exist
        if User.query.count() == 0:
            print("📝 Creating default users...")
            teacher = User(
                email='teacher@studygrind.com',
                password=generate_password_hash('teacher123'),
                name='Professor Smith',
                role='teacher'
            )
            
            student = User(
                email='student@studygrind.com',
                password=generate_password_hash('student123'),
                name='John Student',
                role='student'
            )
            
            db.session.add(teacher)
            db.session.add(student)
            db.session.commit()
            
            # Create sample events
            if Event.query.count() == 0:
                print("📅 Creating sample events...")
                now = datetime.utcnow()
                event1 = Event(
                    title='Mathematics Class',
                    description='Weekly mathematics lecture',
                    event_type='class',
                    start_date=now + timedelta(days=1, hours=9),
                    end_date=now + timedelta(days=1, hours=11),
                    location='Room 101',
                    color='#2196f3',
                    created_by=teacher.id
                )
                event2 = Event(
                    title='Physics Exam',
                    description='Mid-term examination',
                    event_type='exam',
                    start_date=now + timedelta(days=7, hours=10),
                    end_date=now + timedelta(days=7, hours=12),
                    location='Exam Hall',
                    color='#f44336',
                    created_by=teacher.id
                )
                event3 = Event(
                    title='Assignment Due: Essay',
                    description='Submit your final essay',
                    event_type='assignment',
                    start_date=now + timedelta(days=3, hours=23, minutes=59),
                    end_date=now + timedelta(days=3, hours=23, minutes=59),
                    location='Online',
                    color='#ff9800',
                    created_by=teacher.id
                )
                db.session.add_all([event1, event2, event3])
            
            # Create sample notes
            if Note.query.count() == 0:
                print("📝 Creating sample notes...")
                sample_note = Note(
                    title='Welcome to StudyGrind',
                    content='This is a sample note to get you started! You can create your own notes, view teacher notes, and access study materials.',
                    subject='Orientation',
                    user_id=student.id
                )
                
                teacher_note = Note(
                    title='Introduction to Python Programming',
                    content='Python is a high-level, interpreted programming language known for its simplicity and readability.',
                    subject='Computer Science',
                    user_id=teacher.id,
                    is_public=True,
                    is_teacher_note=True
                )
                db.session.add_all([sample_note, teacher_note])
            
            # Create sample link
            if Link.query.count() == 0:
                print("🔗 Creating sample links...")
                sample_link = Link(
                    title='Python Official Documentation',
                    url='https://docs.python.org/3/',
                    description='Official Python documentation - tutorials, library reference, and more.',
                    subject='Computer Science',
                    created_by=teacher.id
                )
                db.session.add(sample_link)
            
            db.session.commit()
            print("✅ Database initialized with default users")
            print("   Teacher: teacher@studygrind.com / teacher123")
            print("   Student: student@studygrind.com / student123")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")
        db.session.rollback()

def create_upload_directories():
    """Create upload directories if they don't exist"""
    try:
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks'), exist_ok=True)
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'resources'), exist_ok=True)
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'submissions'), exist_ok=True)
        print(f"✅ Upload directories created in {app.config['UPLOAD_FOLDER']}")
    except Exception as e:
        print(f"⚠️ Warning: Could not create upload directories: {e}")

# Initialize database and upload directories when the app starts
with app.app_context():
    init_db()
    create_upload_directories()

# ========== API ROUTES ==========

# Authentication Routes
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        login_user(user, remember=True)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Login successful',
            'user': user.serialize,
            'redirect': '/teacher' if user.role == 'teacher' else '/student'
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        role = data.get('role', 'student')
        
        if not email or not password or not name:
            return jsonify({'error': 'All fields required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        user = User(
            email=email,
            password=generate_password_hash(password),
            name=name,
            role=role
        )
        
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        
        return jsonify({
            'message': 'Registration successful',
            'user': user.serialize,
            'redirect': '/teacher' if role == 'teacher' else '/student'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/check-auth')
def check_auth():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': current_user.serialize
        }), 200
    return jsonify({'authenticated': False}), 200

# Notes Routes
@app.route('/api/notes', methods=['GET'])
@login_required
def get_notes():
    try:
        notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
        return jsonify({'notes': [note.serialize for note in notes]}), 200
    except Exception as e:
        print(f"Error getting notes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/public', methods=['GET'])
@login_required
def get_public_notes():
    try:
        if current_user.role == 'teacher':
            notes = Note.query.filter_by(is_public=True, is_teacher_note=True).order_by(Note.updated_at.desc()).all()
        else:
            notes = Note.query.filter_by(is_public=True).order_by(Note.updated_at.desc()).all()
        return jsonify({'notes': [note.serialize for note in notes]}), 200
    except Exception as e:
        print(f"Error getting public notes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/<int:note_id>', methods=['GET'])
@login_required
def get_note(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        if not note.is_public and note.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        return jsonify({'note': note.serialize}), 200
    except Exception as e:
        print(f"Error getting note: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes', methods=['POST'])
@login_required
def create_note():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        note = Note(
            title=data.get('title', 'Untitled'),
            content=data.get('content', ''),
            subject=data.get('subject'),
            tags=data.get('tags'),
            user_id=current_user.id,
            is_public=data.get('is_public', False),
            is_teacher_note=(current_user.role == 'teacher')
        )
        
        db.session.add(note)
        db.session.commit()
        
        # Notify students if teacher note is public
        if note.is_public and note.is_teacher_note:
            students = User.query.filter_by(role='student').all()
            for student in students:
                create_notification(
                    user_id=student.id,
                    type='note',
                    title=f'New Note: {note.title}',
                    message=f'Teacher shared a new note: {note.title}'
                )
        
        return jsonify({'note': note.serialize, 'message': 'Note created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating note: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@login_required
def update_note(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        if note.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        note.title = data.get('title', note.title)
        note.content = data.get('content', note.content)
        note.subject = data.get('subject', note.subject)
        note.tags = data.get('tags', note.tags)
        note.is_public = data.get('is_public', note.is_public)
        note.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'note': note.serialize, 'message': 'Note updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating note: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        if note.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(note)
        db.session.commit()
        return jsonify({'message': 'Note deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting note: {e}")
        return jsonify({'error': str(e)}), 500

# Textbooks Routes
@app.route('/api/textbooks', methods=['GET'])
@login_required
def get_textbooks():
    try:
        textbooks = Textbook.query.order_by(Textbook.created_at.desc()).all()
        return jsonify({'textbooks': [tb.serialize for tb in textbooks]}), 200
    except Exception as e:
        print(f"Error getting textbooks: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks', methods=['POST'])
@login_required
def upload_textbook():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can upload textbooks'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        filename, file_size = save_uploaded_file(file, 'textbooks')
        
        textbook = Textbook(
            title=request.form.get('title', 'Untitled Textbook'),
            author=request.form.get('author', 'Unknown'),
            description=request.form.get('description', ''),
            subject=request.form.get('subject', 'General'),
            filename=filename,
            file_size=file_size,
            uploaded_by=current_user.id
        )
        
        db.session.add(textbook)
        db.session.commit()
        
        # Notify students
        students = User.query.filter_by(role='student').all()
        for student in students:
            create_notification(
                user_id=student.id,
                type='resource',
                title=f'New Textbook: {textbook.title}',
                message=f'A new textbook "{textbook.title}" has been uploaded.'
            )
        
        return jsonify({'textbook': textbook.serialize, 'message': 'Textbook uploaded successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error uploading textbook: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks/<int:textbook_id>', methods=['DELETE'])
@login_required
def delete_textbook(textbook_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can delete textbooks'}), 403
        
        textbook = Textbook.query.get_or_404(textbook_id)
        if textbook.uploaded_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks', textbook.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(textbook)
        db.session.commit()
        
        return jsonify({'message': 'Textbook deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting textbook: {e}")
        return jsonify({'error': str(e)}), 500

# Resources Routes
@app.route('/api/resources', methods=['GET'])
@login_required
def get_resources():
    try:
        resources = Resource.query.order_by(Resource.created_at.desc()).all()
        return jsonify({'resources': [r.serialize for r in resources]}), 200
    except Exception as e:
        print(f"Error getting resources: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/resources', methods=['POST'])
@login_required
def upload_resource():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can upload resources'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        filename, file_size = save_uploaded_file(file, 'resources')
        
        resource = Resource(
            title=request.form.get('title', 'Untitled Resource'),
            description=request.form.get('description', ''),
            resource_type=request.form.get('resource_type', 'other'),
            subject=request.form.get('subject', 'General'),
            filename=filename,
            file_size=file_size,
            uploaded_by=current_user.id
        )
        
        db.session.add(resource)
        db.session.commit()
        
        # Notify students
        students = User.query.filter_by(role='student').all()
        for student in students:
            create_notification(
                user_id=student.id,
                type='resource',
                title=f'New Resource: {resource.title}',
                message=f'A new resource "{resource.title}" has been uploaded.'
            )
        
        return jsonify({'resource': resource.serialize, 'message': 'Resource uploaded successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error uploading resource: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/resources/<int:resource_id>', methods=['DELETE'])
@login_required
def delete_resource(resource_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can delete resources'}), 403
        
        resource = Resource.query.get_or_404(resource_id)
        if resource.uploaded_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', resource.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(resource)
        db.session.commit()
        
        return jsonify({'message': 'Resource deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting resource: {e}")
        return jsonify({'error': str(e)}), 500

# Links Routes
@app.route('/api/links', methods=['GET'])
@login_required
def get_links():
    try:
        links = Link.query.order_by(Link.created_at.desc()).all()
        return jsonify({'links': [link.serialize for link in links]}), 200
    except Exception as e:
        print(f"Error getting links: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/links', methods=['POST'])
@login_required
def create_link():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can create links'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        link = Link(
            title=data.get('title', 'Untitled Link'),
            url=data.get('url', '#'),
            description=data.get('description', ''),
            subject=data.get('subject', 'General'),
            created_by=current_user.id
        )
        
        db.session.add(link)
        db.session.commit()
        
        # Notify students
        students = User.query.filter_by(role='student').all()
        for student in students:
            create_notification(
                user_id=student.id,
                type='link',
                title=f'New Link: {link.title}',
                message=f'A new resource link "{link.title}" has been shared.'
            )
        
        return jsonify({'link': link.serialize, 'message': 'Link created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating link: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/links/<int:link_id>', methods=['DELETE'])
@login_required
def delete_link(link_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can delete links'}), 403
        
        link = Link.query.get_or_404(link_id)
        if link.created_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(link)
        db.session.commit()
        
        return jsonify({'message': 'Link deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting link: {e}")
        return jsonify({'error': str(e)}), 500

# Assignments Routes
@app.route('/api/assignments', methods=['GET'])
@login_required
def get_assignments():
    try:
        if current_user.role == 'teacher':
            assignments = Assignment.query.filter_by(created_by=current_user.id).order_by(Assignment.due_date.desc()).all()
        else:
            assignments = Assignment.query.filter_by(is_active=True).order_by(Assignment.due_date.asc()).all()
        
        return jsonify({'assignments': [a.serialize for a in assignments]}), 200
    except Exception as e:
        print(f"Error getting assignments: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    try:
        assignment = Assignment.query.get_or_404(assignment_id)
        return jsonify({'assignment': assignment.serialize}), 200
    except Exception as e:
        print(f"Error getting assignment: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments', methods=['POST'])
@login_required
def create_assignment():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can create assignments'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not data.get('title'):
            return jsonify({'error': 'Title is required'}), 400
        if not data.get('due_date'):
            return jsonify({'error': 'Due date is required'}), 400
        
        try:
            due_date = datetime.fromisoformat(data.get('due_date').replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid due date format'}), 400
        
        if due_date < datetime.utcnow():
            return jsonify({'error': 'Due date must be in the future'}), 400
        
        assignment = Assignment(
            title=data.get('title'),
            description=data.get('description', ''),
            instructions=data.get('instructions', ''),
            subject=data.get('subject', 'General'),
            max_score=int(data.get('max_score', 100)),
            due_date=due_date,
            created_by=current_user.id
        )
        
        db.session.add(assignment)
        db.session.commit()
        
        # Notify students
        students = User.query.filter_by(role='student').all()
        for student in students:
            create_notification(
                user_id=student.id,
                type='assignment',
                title=f'New Assignment: {assignment.title}',
                message=f'A new assignment "{assignment.title}" has been created. Due: {due_date.strftime("%B %d, %Y")}'
            )
        
        return jsonify({'assignment': assignment.serialize, 'message': 'Assignment created successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating assignment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
def delete_assignment(assignment_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can delete assignments'}), 403
        
        assignment = Assignment.query.get_or_404(assignment_id)
        if assignment.created_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(assignment)
        db.session.commit()
        
        return jsonify({'message': 'Assignment deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting assignment: {e}")
        return jsonify({'error': str(e)}), 500

# Submissions Routes
@app.route('/api/submissions', methods=['POST'])
@login_required
def submit_assignment():
    try:
        if current_user.role != 'student':
            return jsonify({'error': 'Only students can submit assignments'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        existing = Submission.query.filter_by(
            assignment_id=data.get('assignment_id'),
            student_id=current_user.id
        ).first()
        
        if existing:
            return jsonify({'error': 'Assignment already submitted'}), 400
        
        assignment = Assignment.query.get(data.get('assignment_id'))
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        submission = Submission(
            assignment_id=data.get('assignment_id'),
            student_id=current_user.id,
            content=data.get('content', '')
        )
        
        db.session.add(submission)
        db.session.commit()
        
        # Notify teacher
        if assignment.creator:
            create_notification(
                user_id=assignment.created_by,
                type='submission',
                title=f'New Submission: {assignment.title}',
                message=f'{current_user.name} submitted {assignment.title}.'
            )
        
        return jsonify({'submission': submission.serialize, 'message': 'Assignment submitted successfully'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error submitting assignment: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions', methods=['GET'])
@login_required
def get_all_submissions():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Unauthorized'}), 403
        
        assignment_id = request.args.get('assignment_id', type=int)
        
        query = Submission.query.order_by(Submission.submitted_at.desc())
        if assignment_id:
            query = query.filter_by(assignment_id=assignment_id)
        
        submissions = query.all()
        return jsonify({'submissions': [s.serialize for s in submissions]}), 200
        
    except Exception as e:
        print(f"Error getting submissions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions/<int:submission_id>/grade', methods=['POST'])
@login_required
def grade_submission(submission_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can grade submissions'}), 403
        
        submission = Submission.query.get_or_404(submission_id)
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'grade' in data:
            submission.grade = data.get('grade')
        if 'feedback' in data:
            submission.feedback = data.get('feedback')
        
        submission.graded_at = datetime.utcnow()
        db.session.commit()
        
        # Notify student
        create_notification(
            user_id=submission.student_id,
            type='grade',
            title=f'Assignment Graded: {submission.assignment.title}',
            message=f'Your submission has been graded. Score: {submission.grade}'
        )
        
        return jsonify({'submission': submission.serialize, 'message': 'Submission graded successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error grading submission: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/student/submissions', methods=['GET'])
@login_required
def get_student_submissions():
    try:
        if current_user.role != 'student':
            return jsonify({'error': 'Unauthorized'}), 403
        
        submissions = Submission.query.filter_by(student_id=current_user.id).all()
        return jsonify({'submissions': [s.serialize for s in submissions]}), 200
    except Exception as e:
        print(f"Error getting student submissions: {e}")
        return jsonify({'error': str(e)}), 500

# Students Routes
@app.route('/api/students', methods=['GET'])
@login_required
def get_students():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Unauthorized'}), 403
        
        students = User.query.filter_by(role='student').all()
        return jsonify({'students': [s.serialize for s in students]}), 200
    except Exception as e:
        print(f"Error getting students: {e}")
        return jsonify({'error': str(e)}), 500

# Events Routes
@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        query = Event.query.order_by(Event.start_date)
        
        if start_date:
            try:
                start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query = query.filter(Event.start_date >= start)
            except (ValueError, TypeError):
                pass
        
        if end_date:
            try:
                end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                query = query.filter(Event.start_date <= end)
            except (ValueError, TypeError):
                pass
        
        # Students can see all events, teachers see their own
        if current_user.role == 'teacher':
            query = query.filter_by(created_by=current_user.id)
        
        events = query.all()
        return jsonify({'events': [e.serialize for e in events]}), 200
        
    except Exception as e:
        print(f"Error getting events: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can create events'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not data.get('title'):
            return jsonify({'error': 'Title is required'}), 400
        if not data.get('start_date'):
            return jsonify({'error': 'Start date is required'}), 400
        
        try:
            start_date = datetime.fromisoformat(data.get('start_date').replace('Z', '+00:00'))
        except (ValueError, TypeError) as e:
            return jsonify({'error': f'Invalid start date format: {str(e)}'}), 400
        
        end_date = None
        if data.get('end_date'):
            try:
                end_date = datetime.fromisoformat(data.get('end_date').replace('Z', '+00:00'))
            except (ValueError, TypeError):
                end_date = start_date + timedelta(hours=1)
        
        event = Event(
            title=data.get('title'),
            description=data.get('description', ''),
            event_type=data.get('event_type', 'class'),
            start_date=start_date,
            end_date=end_date,
            all_day=data.get('all_day', False),
            location=data.get('location', ''),
            color=data.get('color', '#2196f3'),
            created_by=current_user.id
        )
        
        db.session.add(event)
        db.session.commit()
        
        # Notify students
        if current_user.role == 'teacher':
            students = User.query.filter_by(role='student').all()
            for student in students:
                create_notification(
                    user_id=student.id,
                    type='event',
                    title=f'New Event: {event.title}',
                    message=f'A new event "{event.title}" has been scheduled for {start_date.strftime("%B %d, %Y at %I:%M %p")}'
                )
        
        return jsonify({'event': event.serialize, 'message': 'Event created successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating event: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
def get_event(event_id):
    try:
        event = Event.query.get_or_404(event_id)
        
        # Check permission - students can view any event, teachers can only view their own
        if current_user.role == 'teacher' and event.created_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        return jsonify({'event': event.serialize}), 200
        
    except Exception as e:
        print(f"Error getting event: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can update events'}), 403
        
        event = Event.query.get_or_404(event_id)
        if event.created_by != current_user.id:
            return jsonify({'error': 'You can only update your own events'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'title' in data:
            event.title = data['title']
        if 'description' in data:
            event.description = data['description']
        if 'event_type' in data:
            event.event_type = data['event_type']
        if 'start_date' in data:
            try:
                event.start_date = datetime.fromisoformat(data['start_date'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        if 'end_date' in data:
            try:
                event.end_date = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        if 'all_day' in data:
            event.all_day = data['all_day']
        if 'location' in data:
            event.location = data['location']
        if 'color' in data:
            event.color = data['color']
        
        db.session.commit()
        
        return jsonify({'event': event.serialize, 'message': 'Event updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating event: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can delete events'}), 403
        
        event = Event.query.get_or_404(event_id)
        if event.created_by != current_user.id:
            return jsonify({'error': 'You can only delete your own events'}), 403
        
        db.session.delete(event)
        db.session.commit()
        
        return jsonify({'message': 'Event deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting event: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Notifications Routes
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    try:
        notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
        return jsonify({'notifications': [n.serialize for n in notifications]}), 200
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = Notification.query.get_or_404(notification_id)
        if notification.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        notification.is_read = True
        db.session.commit()
        return jsonify({'message': 'Notification marked as read'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notification read: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'message': 'All notifications marked as read'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error marking all notifications read: {e}")
        return jsonify({'error': str(e)}), 500

# Download Routes
@app.route('/api/download/<file_type>/<filename>')
@login_required
def download_file(file_type, filename):
    try:
        if file_type not in ['textbooks', 'resources']:
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Security check
        if '..' in filename or filename.startswith('/') or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_type, filename)
        
        # Security check: ensure file is within upload directory
        real_upload = os.path.realpath(app.config['UPLOAD_FOLDER'])
        real_file = os.path.realpath(file_path)
        if not real_file.startswith(real_upload):
            return jsonify({'error': 'Access denied'}), 403
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Track download
        if file_type == 'textbooks':
            textbook = Textbook.query.filter_by(filename=filename).first()
            if textbook:
                textbook.downloads += 1
                db.session.commit()
        elif file_type == 'resources':
            resource = Resource.query.filter_by(filename=filename).first()
            if resource:
                resource.downloads += 1
                db.session.commit()
        
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({'error': 'Download failed'}), 500

# Dashboard Data
@app.route('/api/dashboard-data')
@login_required
def get_dashboard_data():
    try:
        if current_user.role == 'teacher':
            notes_count = Note.query.filter_by(user_id=current_user.id).count()
            textbooks_count = Textbook.query.filter_by(uploaded_by=current_user.id).count()
            resources_count = Resource.query.filter_by(uploaded_by=current_user.id).count()
            links_count = Link.query.filter_by(created_by=current_user.id).count()
            students_count = User.query.filter_by(role='student').count()
            assignments_count = Assignment.query.filter_by(created_by=current_user.id).count()
            
            now = datetime.utcnow()
            events_count = Event.query.filter_by(created_by=current_user.id).filter(Event.start_date >= now).count()
            
            recent_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).limit(4).all()
            recent_resources = Resource.query.filter_by(uploaded_by=current_user.id).order_by(Resource.created_at.desc()).limit(4).all()
            recent_links = Link.query.filter_by(created_by=current_user.id).order_by(Link.created_at.desc()).limit(4).all()
            upcoming_events = Event.query.filter_by(created_by=current_user.id).filter(Event.start_date >= now).order_by(Event.start_date).limit(5).all()
            
            return jsonify({
                'stats': {
                    'notes': notes_count,
                    'textbooks': textbooks_count,
                    'resources': resources_count,
                    'links': links_count,
                    'students': students_count,
                    'assignments': assignments_count,
                    'events': events_count
                },
                'recent_notes': [n.serialize for n in recent_notes],
                'recent_resources': [r.serialize for r in recent_resources],
                'recent_links': [l.serialize for l in recent_links],
                'upcoming_events': [e.serialize for e in upcoming_events]
            }), 200
            
        else:  # Student
            notes_count = Note.query.filter_by(user_id=current_user.id).count()
            textbooks_count = Textbook.query.count()
            resources_count = Resource.query.count()
            links_count = Link.query.count()
            
            assignments = Assignment.query.filter_by(is_active=True).all()
            submitted_assignments = [s.assignment_id for s in Submission.query.filter_by(student_id=current_user.id).all()]
            pending_assignments_count = len([a for a in assignments if a.id not in submitted_assignments])
            
            now = datetime.utcnow()
            upcoming_events = Event.query.filter(Event.start_date >= now).order_by(Event.start_date).limit(5).all()
            
            personal_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).limit(4).all()
            teacher_notes = Note.query.filter_by(is_public=True, is_teacher_note=True).order_by(Note.updated_at.desc()).limit(4).all()
            recent_links = Link.query.order_by(Link.created_at.desc()).limit(4).all()
            
            return jsonify({
                'stats': {
                    'notes': notes_count,
                    'textbooks': textbooks_count,
                    'resources': resources_count,
                    'links': links_count,
                    'assignments': pending_assignments_count,
                    'events': len(upcoming_events)
                },
                'personal_notes': [n.serialize for n in personal_notes],
                'teacher_notes': [n.serialize for n in teacher_notes],
                'recent_links': [l.serialize for l in recent_links],
                'upcoming_events': [e.serialize for e in upcoming_events]
            }), 200
            
    except Exception as e:
        print(f"Dashboard error: {e}")
        return jsonify({'error': str(e)}), 500

# ========== PAGE ROUTES ==========

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/teacher')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect('/student')
    return render_template('teacher.html')

@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect('/teacher')
    return render_template('student.html')

# ========== MAIN EXECUTION ==========
# This block only runs when executing python app.py directly (for local development)
if __name__ == '__main__':
    # Get port from environment variable
    port = int(os.environ.get('PORT', 5000))
    
    print("=" * 60)
    print("📚 StudyGrind - Complete Learning Management System")
    print("=" * 60)
    print("\n✅ Features Implemented:")
    print("   • User authentication (teacher/student)")
    print("   • Notes management (create, edit, delete, public/private)")
    print("   • Textbook & resource uploads/downloads")
    print("   • Links management for study resources")
    print("   • Assignments with submissions and grading")
    print("   • Calendar events (classes, exams, due dates)")
    print("   • In-app notifications")
    print("   • Student list view for teachers")
    print("   • Dashboard with statistics")
    print(f"\n🌐 Server: http://localhost:{port}")
    print("\n👤 Test Accounts:")
    print("   Teacher: teacher@studygrind.com / teacher123")
    print("   Student: student@studygrind.com / student123")
    print(f"\n📁 Upload folder:", os.path.abspath(app.config['UPLOAD_FOLDER']))
    print("=" * 60)
    
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=False)
