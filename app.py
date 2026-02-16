"""
StudyGrind - Educational Platform
A Flask-based learning management system with role-based access control
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, Union
from functools import wraps

from flask import Flask, request, jsonify, render_template, send_file, redirect
from flask_login import login_required, logout_user, current_user, LoginManager, login_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates')

# Configuration class
class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    SESSION_COOKIE_DOMAIN = None
    SESSION_COOKIE_PATH = '/'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_DOMAIN = None
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=31)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt',
        'jpg', 'jpeg', 'png', 'gif', 'mp4', 'avi', 'mov'
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///studygrind.db'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///data/studygrind.db'
    ).replace('postgres://', 'postgresql://')  # For Heroku compatibility

# Select configuration based on environment
if os.environ.get('RENDER'):
    app.config.from_object(ProductionConfig)
    # Ensure data directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)
else:
    app.config.from_object(DevelopmentConfig)

# Initialize extensions
db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://studygrind-1.onrender.com"
])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

# Ensure upload directories exist
def ensure_directories() -> None:
    """Create necessary directories if they don't exist"""
    dirs = ['textbooks', 'resources', 'assignments', 'submissions']
    base_upload = app.config['UPLOAD_FOLDER']
    
    # Create base upload directory
    os.makedirs(base_upload, exist_ok=True)
    
    # Create subdirectories
    for dir_name in dirs:
        os.makedirs(os.path.join(base_upload, dir_name), exist_ok=True)
    
    # Create data directory for database
    os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)

ensure_directories()

# ============================================================================
# Database Models
# ============================================================================

class User(db.Model, UserMixin):
    """User model for both students and teachers"""
    __tablename__ = 'users'
    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_role', 'role'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize user object to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }
    
    @property
    def is_teacher(self) -> bool:
        """Check if user is a teacher"""
        return self.role == 'teacher'
    
    @property
    def is_student(self) -> bool:
        """Check if user is a student"""
        return self.role == 'student'

class Note(db.Model):
    """Note model for user notes"""
    __tablename__ = 'notes'
    __table_args__ = (
        db.Index('idx_note_user', 'user_id'),
        db.Index('idx_note_public', 'is_public'),
    )
    
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
    def serialize(self) -> Dict[str, Any]:
        """Serialize note object to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'subject': self.subject,
            'tags': self.tags.split(',') if self.tags else [],
            'user_id': self.user_id,
            'user_name': self.user.name if self.user else '',
            'is_public': self.is_public,
            'is_teacher_note': self.is_teacher_note,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Textbook(db.Model):
    """Textbook model for uploaded textbooks"""
    __tablename__ = 'textbooks'
    __table_args__ = (
        db.Index('idx_textbook_uploader', 'uploaded_by'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200))
    description = db.Column(db.Text)
    subject = db.Column(db.String(100))
    filename = db.Column(db.String(300))
    file_size = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    uploader = db.relationship('User', backref='textbooks')
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize textbook object to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'description': self.description,
            'subject': self.subject,
            'filename': self.filename,
            'file_size': self.file_size,
            'file_size_formatted': self._format_file_size(),
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.name if self.uploader else '',
            'created_at': self.created_at.isoformat()
        }
    
    def _format_file_size(self) -> str:
        """Format file size for display"""
        if not self.file_size:
            return 'Unknown'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} TB"

class Resource(db.Model):
    """Resource model for uploaded resources"""
    __tablename__ = 'resources'
    __table_args__ = (
        db.Index('idx_resource_uploader', 'uploaded_by'),
        db.Index('idx_resource_type', 'resource_type'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    resource_type = db.Column(db.String(50))
    subject = db.Column(db.String(100))
    filename = db.Column(db.String(300))
    file_size = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    uploader = db.relationship('User', backref='resources')
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize resource object to dictionary"""
        type_labels = {
            'lecture': 'Lecture Notes',
            'assignment': 'Assignment',
            'practice_test': 'Practice Test',
            'video': 'Video',
            'other': 'Resource'
        }
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'resource_type': self.resource_type,
            'resource_type_label': type_labels.get(self.resource_type, 'Resource'),
            'subject': self.subject,
            'filename': self.filename,
            'file_size': self.file_size,
            'file_size_formatted': self._format_file_size(),
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.name if self.uploader else '',
            'created_at': self.created_at.isoformat()
        }
    
    def _format_file_size(self) -> str:
        """Format file size for display"""
        if not self.file_size:
            return 'Unknown'
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

class Assignment(db.Model):
    """Assignment model for teacher-created assignments"""
    __tablename__ = 'assignments'
    __table_args__ = (
        db.Index('idx_assignment_creator', 'created_by'),
        db.Index('idx_assignment_due', 'due_date'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    instructions = db.Column(db.Text)
    subject = db.Column(db.String(100))
    max_score = db.Column(db.Integer, default=100)
    due_date = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='assignments')
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize assignment object to dictionary"""
        days_remaining = None
        if self.due_date:
            delta = self.due_date - datetime.utcnow()
            days_remaining = delta.days
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'instructions': self.instructions,
            'subject': self.subject,
            'max_score': self.max_score,
            'due_date': self.due_date.isoformat(),
            'due_date_formatted': self.due_date.strftime('%B %d, %Y'),
            'created_by': self.created_by,
            'creator_name': self.creator.name if self.creator else '',
            'created_at': self.created_at.isoformat(),
            'days_remaining': days_remaining,
            'status': self._get_status(days_remaining)
        }
    
    def _get_status(self, days_remaining: Optional[int]) -> str:
        """Get assignment status based on due date"""
        if days_remaining is None:
            return 'Unknown'
        if days_remaining < 0:
            return 'Overdue'
        if days_remaining == 0:
            return 'Due Today'
        if days_remaining <= 7:
            return 'Due Soon'
        return 'Open'

class Submission(db.Model):
    """Submission model for student assignment submissions"""
    __tablename__ = 'submissions'
    __table_args__ = (
        db.Index('idx_submission_assignment', 'assignment_id'),
        db.Index('idx_submission_student', 'student_id'),
        db.UniqueConstraint('assignment_id', 'student_id', name='unique_submission'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text)
    filename = db.Column(db.String(300))
    grade = db.Column(db.Float)
    feedback = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    graded_at = db.Column(db.DateTime)
    
    assignment = db.relationship('Assignment', backref=db.backref('submissions', cascade='all, delete-orphan'))
    student = db.relationship('User', backref='submissions')
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize submission object to dictionary"""
        return {
            'id': self.id,
            'assignment_id': self.assignment_id,
            'student_id': self.student_id,
            'student_name': self.student.name if self.student else '',
            'content': self.content,
            'filename': self.filename,
            'grade': self.grade,
            'grade_percentage': f"{(self.grade / self.assignment.max_score * 100):.1f}%" if self.grade and self.assignment else None,
            'feedback': self.feedback,
            'submitted_at': self.submitted_at.isoformat(),
            'graded_at': self.graded_at.isoformat() if self.graded_at else None,
            'assignment_title': self.assignment.title if self.assignment else '',
            'is_graded': self.grade is not None
        }

class Event(db.Model):
    """Event model for calendar events"""
    __tablename__ = 'events'
    __table_args__ = (
        db.Index('idx_event_creator', 'created_by'),
        db.Index('idx_event_dates', 'start_date', 'end_date'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    event_type = db.Column(db.String(50))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    all_day = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(20), default='#4caf50')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='events')
    
    @property
    def serialize(self) -> Dict[str, Any]:
        """Serialize event object to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'event_type': self.event_type,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'all_day': self.all_day,
            'color': self.color,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat()
        }

# ============================================================================
# User Loader
# ============================================================================

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load user by ID for Flask-Login"""
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# ============================================================================
# Decorators
# ============================================================================

def role_required(*roles: str):
    """Decorator to restrict access to specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            if current_user.role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def handle_errors(f):
    """Decorator to handle exceptions in routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
            return jsonify({'error': 'An internal server error occurred'}), 500
    return decorated_function

# ============================================================================
# Helper Functions
# ============================================================================

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_file_size(file: FileStorage) -> int:
    """Get file size in bytes"""
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size

def validate_file_upload(file: FileStorage, required: bool = True) -> Tuple[bool, str, Optional[Dict]]:
    """Validate file upload with detailed error messages"""
    if not file and required:
        return False, 'No file uploaded', None
    
    if file and file.filename == '':
        return False, 'No file selected', None
    
    if file and not allowed_file(file.filename):
        return False, f'File type not allowed. Allowed types: {", ".join(app.config["ALLOWED_EXTENSIONS"])}', None
    
    if file and file.content_length and file.content_length > app.config['MAX_CONTENT_LENGTH']:
        max_mb = app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
        return False, f'File too large. Maximum size: {max_mb}MB', None
    
    return True, 'OK', {
        'filename': secure_filename(file.filename),
        'size': get_file_size(file) if file else 0
    }

def save_uploaded_file(file: FileStorage, subfolder: str) -> str:
    """Save uploaded file with unique filename to prevent overwrites"""
    filename = secure_filename(file.filename)
    base_name, ext = os.path.splitext(filename)
    
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, filename)
    counter = 1
    
    while os.path.exists(file_path):
        new_filename = f"{base_name}_{counter}{ext}"
        file_path = os.path.join(upload_dir, new_filename)
        counter += 1
    
    file.save(file_path)
    return os.path.basename(file_path)

# ============================================================================
# Database Initialization
# ============================================================================

def init_db() -> None:
    """Initialize database with tables and default users"""
    with app.app_context():
        db.create_all()
        logger.info("Database tables created/verified")
        
        # Create default users if none exist
        if not User.query.first():
            logger.info("Creating default users...")
            
            default_users = [
                User(
                    email='teacher@studygrind.com',
                    password=generate_password_hash('teacher123'),
                    name='Professor Smith',
                    role='teacher'
                ),
                User(
                    email='student@studygrind.com',
                    password=generate_password_hash('student123'),
                    name='John Student',
                    role='student'
                )
            ]
            
            for user in default_users:
                db.session.add(user)
            
            db.session.commit()
            logger.info("Default users created successfully")

# Run database initialization
with app.app_context():
    init_db()

# ============================================================================
# Route Handlers
# ============================================================================

# Public routes
@app.route('/')
def index():
    """Redirect root to login page"""
    return redirect('/login')

@app.route('/login')
def login_page():
    """Render login page"""
    return render_template('login.html')

@app.route('/teacher')
@login_required
def teacher_dashboard():
    """Render teacher dashboard"""
    if not current_user.is_teacher:
        return redirect('/student')
    return render_template('teacher.html')

@app.route('/student')
@login_required
def student_dashboard():
    """Render student dashboard"""
    if not current_user.is_student:
        return redirect('/teacher')
    return render_template('student.html')

# ============================================================================
# API Routes
# ============================================================================

@app.route('/api/login', methods=['POST'])
@handle_errors
def login():
    """Authenticate user and create session"""
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    login_user(user, remember=True)
    logger.info(f"User logged in: {email} ({user.role})")
    
    return jsonify({
        'message': 'Login successful',
        'user': user.serialize,
        'redirect': '/teacher' if user.is_teacher else '/student'
    }), 200

@app.route('/api/signup', methods=['POST'])
@handle_errors
def signup():
    """Register new user"""
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    role = data.get('role', 'student')
    
    if not all([email, password, name]):
        return jsonify({'error': 'All fields are required'}), 400
    
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
    
    logger.info(f"New user registered: {email} ({role})")
    
    return jsonify({
        'message': 'Registration successful',
        'user': user.serialize,
        'redirect': '/teacher' if role == 'teacher' else '/student'
    }), 201

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Log out current user"""
    email = current_user.email
    logout_user()
    logger.info(f"User logged out: {email}")
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/check-auth')
def check_auth():
    """Check if user is authenticated"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': current_user.serialize
        }), 200
    return jsonify({'authenticated': False}), 200

# ============================================================================
# Notes API
# ============================================================================

@app.route('/api/notes', methods=['GET'])
@login_required
@handle_errors
def get_notes():
    """Get all notes for current user"""
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return jsonify({'notes': [note.serialize for note in notes]}), 200

@app.route('/api/notes/public', methods=['GET'])
@login_required
@handle_errors
def get_public_notes():
    """Get all public notes (teacher notes)"""
    notes = Note.query.filter_by(is_public=True, is_teacher_note=True).all()
    return jsonify({'notes': [note.serialize for note in notes]}), 200

@app.route('/api/notes/<int:note_id>', methods=['GET'])
@login_required
@handle_errors
def get_note(note_id: int):
    """Get a specific note by ID"""
    note = Note.query.get_or_404(note_id)
    
    # Check permissions: user can view if they own it or it's public
    if note.user_id != current_user.id and not note.is_public:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({'note': note.serialize}), 200

@app.route('/api/notes', methods=['POST'])
@login_required
@handle_errors
def create_note():
    """Create a new note"""
    data = request.get_json() or {}
    
    # Validate required fields
    if not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    if not data.get('content'):
        return jsonify({'error': 'Content is required'}), 400
    
    note = Note(
        title=data.get('title'),
        content=data.get('content'),
        subject=data.get('subject', ''),
        tags=','.join(data.get('tags', [])) if isinstance(data.get('tags'), list) else data.get('tags', ''),
        user_id=current_user.id,
        is_public=data.get('is_public', False),
        is_teacher_note=current_user.is_teacher
    )
    
    db.session.add(note)
    db.session.commit()
    
    logger.info(f"Note created: {note.title} by user {current_user.id}")
    
    return jsonify({
        'note': note.serialize,
        'message': 'Note created successfully'
    }), 201

@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@login_required
@handle_errors
def update_note(note_id: int):
    """Update an existing note"""
    note = Note.query.get_or_404(note_id)
    
    if note.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json() or {}
    
    note.title = data.get('title', note.title)
    note.content = data.get('content', note.content)
    note.subject = data.get('subject', note.subject)
    
    # Handle tags (can be string or list)
    tags = data.get('tags', note.tags)
    if isinstance(tags, list):
        note.tags = ','.join(tags)
    else:
        note.tags = tags
    
    note.is_public = data.get('is_public', note.is_public)
    note.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    logger.info(f"Note updated: {note.title} by user {current_user.id}")
    
    return jsonify({
        'note': note.serialize,
        'message': 'Note updated successfully'
    }), 200

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
@handle_errors
def delete_note(note_id: int):
    """Delete a note"""
    note = Note.query.get_or_404(note_id)
    
    if note.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(note)
    db.session.commit()
    
    logger.info(f"Note deleted: ID {note_id} by user {current_user.id}")
    
    return jsonify({'message': 'Note deleted successfully'}), 200

# ============================================================================
# Textbooks API
# ============================================================================

@app.route('/api/textbooks', methods=['GET'])
@login_required
@handle_errors
def get_textbooks():
    """Get all textbooks"""
    textbooks = Textbook.query.order_by(Textbook.created_at.desc()).all()
    return jsonify({'textbooks': [tb.serialize for tb in textbooks]}), 200

@app.route('/api/textbooks', methods=['POST'])
@login_required
@role_required('teacher')
@handle_errors
def upload_textbook():
    """Upload a new textbook (teachers only)"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Validate file
    is_valid, message, file_info = validate_file_upload(file)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    # Save file
    filename = save_uploaded_file(file, 'textbooks')
    
    textbook = Textbook(
        title=request.form.get('title', 'Untitled Textbook'),
        author=request.form.get('author', 'Unknown'),
        description=request.form.get('description', ''),
        subject=request.form.get('subject', 'General'),
        filename=filename,
        file_size=file_info['size'],
        uploaded_by=current_user.id
    )
    
    db.session.add(textbook)
    db.session.commit()
    
    logger.info(f"Textbook uploaded: {textbook.title} by user {current_user.id}")
    
    return jsonify({
        'textbook': textbook.serialize,
        'message': 'Textbook uploaded successfully'
    }), 201

@app.route('/api/textbooks/<int:textbook_id>', methods=['DELETE'])
@login_required
@role_required('teacher')
@handle_errors
def delete_textbook(textbook_id: int):
    """Delete a textbook (teachers only)"""
    textbook = Textbook.query.get_or_404(textbook_id)
    
    if textbook.uploaded_by != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks', textbook.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(textbook)
    db.session.commit()
    
    logger.info(f"Textbook deleted: ID {textbook_id} by user {current_user.id}")
    
    return jsonify({'message': 'Textbook deleted successfully'}), 200

# ============================================================================
# Resources API
# ============================================================================

@app.route('/api/resources', methods=['GET'])
@login_required
@handle_errors
def get_resources():
    """Get all resources"""
    resources = Resource.query.order_by(Resource.created_at.desc()).all()
    return jsonify({'resources': [r.serialize for r in resources]}), 200

@app.route('/api/resources', methods=['POST'])
@login_required
@role_required('teacher')
@handle_errors
def upload_resource():
    """Upload a new resource (teachers only)"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Validate file
    is_valid, message, file_info = validate_file_upload(file)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    # Save file
    filename = save_uploaded_file(file, 'resources')
    
    resource = Resource(
        title=request.form.get('title', 'Untitled Resource'),
        description=request.form.get('description', ''),
        resource_type=request.form.get('resource_type', 'other'),
        subject=request.form.get('subject', 'General'),
        filename=filename,
        file_size=file_info['size'],
        uploaded_by=current_user.id
    )
    
    db.session.add(resource)
    db.session.commit()
    
    logger.info(f"Resource uploaded: {resource.title} by user {current_user.id}")
    
    return jsonify({
        'resource': resource.serialize,
        'message': 'Resource uploaded successfully'
    }), 201

@app.route('/api/resources/<int:resource_id>', methods=['DELETE'])
@login_required
@role_required('teacher')
@handle_errors
def delete_resource(resource_id: int):
    """Delete a resource (teachers only)"""
    resource = Resource.query.get_or_404(resource_id)
    
    if resource.uploaded_by != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', resource.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(resource)
    db.session.commit()
    
    logger.info(f"Resource deleted: ID {resource_id} by user {current_user.id}")
    
    return jsonify({'message': 'Resource deleted successfully'}), 200

# ============================================================================
# Assignments API
# ============================================================================

@app.route('/api/assignments', methods=['GET'])
@login_required
@handle_errors
def get_assignments():
    """Get all assignments"""
    assignments = Assignment.query.order_by(Assignment.due_date).all()
    return jsonify({'assignments': [a.serialize for a in assignments]}), 200

@app.route('/api/assignments/<int:assignment_id>', methods=['GET'])
@login_required
@handle_errors
def get_assignment(assignment_id: int):
    """Get a specific assignment by ID"""
    assignment = Assignment.query.get_or_404(assignment_id)
    return jsonify({'assignment': assignment.serialize}), 200

@app.route('/api/assignments', methods=['POST'])
@login_required
@role_required('teacher')
@handle_errors
def create_assignment():
    """Create a new assignment (teachers only)"""
    data = request.get_json() or {}
    
    # Validate required fields
    if not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    if not data.get('due_date'):
        return jsonify({'error': 'Due date is required'}), 400
    
    try:
        due_date = datetime.fromisoformat(data.get('due_date').replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid due date format'}), 400
    
    assignment = Assignment(
        title=data.get('title'),
        description=data.get('description', ''),
        instructions=data.get('instructions', ''),
        subject=data.get('subject', 'General'),
        max_score=data.get('max_score', 100),
        due_date=due_date,
        created_by=current_user.id
    )
    
    db.session.add(assignment)
    db.session.commit()
    
    logger.info(f"Assignment created: {assignment.title} by user {current_user.id}")
    
    return jsonify({
        'assignment': assignment.serialize,
        'message': 'Assignment created successfully'
    }), 201

@app.route('/api/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
@role_required('teacher')
@handle_errors
def delete_assignment(assignment_id: int):
    """Delete an assignment (teachers only)"""
    assignment = Assignment.query.get_or_404(assignment_id)
    
    if assignment.created_by != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(assignment)
    db.session.commit()
    
    logger.info(f"Assignment deleted: ID {assignment_id} by user {current_user.id}")
    
    return jsonify({'message': 'Assignment deleted successfully'}), 200

# ============================================================================
# Submissions API
# ============================================================================

@app.route('/api/submissions', methods=['POST'])
@login_required
@role_required('student')
@handle_errors
def submit_assignment():
    """Submit an assignment (students only)"""
    data = request.get_json() or {}
    
    assignment_id = data.get('assignment_id')
    content = data.get('content', '')
    
    if not assignment_id:
        return jsonify({'error': 'Assignment ID is required'}), 400
    
    # Check if already submitted
    existing = Submission.query.filter_by(
        assignment_id=assignment_id,
        student_id=current_user.id
    ).first()
    
    if existing:
        return jsonify({'error': 'You have already submitted this assignment'}), 400
    
    submission = Submission(
        assignment_id=assignment_id,
        student_id=current_user.id,
        content=content,
        filename=data.get('filename')
    )
    
    db.session.add(submission)
    db.session.commit()
    
    logger.info(f"Assignment submitted: {assignment_id} by student {current_user.id}")
    
    return jsonify({
        'submission': submission.serialize,
        'message': 'Assignment submitted successfully'
    }), 201

@app.route('/api/submissions/<int:submission_id>/grade', methods=['POST'])
@login_required
@role_required('teacher')
@handle_errors
def grade_submission(submission_id: int):
    """Grade a submission (teachers only)"""
    submission = Submission.query.get_or_404(submission_id)
    data = request.get_json() or {}
    
    grade = data.get('grade')
    if grade is not None:
        # Validate grade
        if grade < 0 or grade > submission.assignment.max_score:
            return jsonify({'error': f'Grade must be between 0 and {submission.assignment.max_score}'}), 400
        submission.grade = grade
    
    submission.feedback = data.get('feedback', submission.feedback)
    submission.graded_at = datetime.utcnow()
    
    db.session.commit()
    
    logger.info(f"Submission graded: {submission_id} by teacher {current_user.id}")
    
    return jsonify({
        'submission': submission.serialize,
        'message': 'Submission graded successfully'
    }), 200

@app.route('/api/student/submissions', methods=['GET'])
@login_required
@role_required('student')
@handle_errors
def get_student_submissions():
    """Get all submissions for current student"""
    submissions = Submission.query.filter_by(student_id=current_user.id).all()
    return jsonify({'submissions': [s.serialize for s in submissions]}), 200

# ============================================================================
# Events API
# ============================================================================

@app.route('/api/events', methods=['GET'])
@login_required
@handle_errors
def get_events():
    """Get all events"""
    events = Event.query.order_by(Event.start_date).all()
    return jsonify({'events': [e.serialize for e in events]}), 200

@app.route('/api/events', methods=['POST'])
@login_required
@handle_errors
def create_event():
    """Create a new event"""
    data = request.get_json() or {}
    
    if not data.get('title'):
        return jsonify({'error': 'Title is required'}), 400
    if not data.get('start_date'):
        return jsonify({'error': 'Start date is required'}), 400
    
    try:
        start_date = datetime.fromisoformat(data.get('start_date').replace('Z', '+00:00'))
        end_date = datetime.fromisoformat(data.get('end_date').replace('Z', '+00:00')) if data.get('end_date') else None
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid date format'}), 400
    
    event = Event(
        title=data.get('title'),
        description=data.get('description', ''),
        event_type=data.get('event_type', 'class'),
        start_date=start_date,
        end_date=end_date,
        all_day=data.get('all_day', False),
        color=data.get('color', '#4caf50'),
        created_by=current_user.id
    )
    
    db.session.add(event)
    db.session.commit()
    
    logger.info(f"Event created: {event.title} by user {current_user.id}")
    
    return jsonify({
        'event': event.serialize,
        'message': 'Event created successfully'
    }), 201

# ============================================================================
# Students API (Teachers only)
# ============================================================================

@app.route('/api/students', methods=['GET'])
@login_required
@role_required('teacher')
@handle_errors
def get_students():
    """Get all students (teachers only)"""
    students = User.query.filter_by(role='student').all()
    
    # Add submission counts
    result = []
    for student in students:
        student_data = student.serialize
        submission_count = Submission.query.filter_by(student_id=student.id).count()
        student_data['submission_count'] = submission_count
        result.append(student_data)
    
    return jsonify({'students': result}), 200

# ============================================================================
# File Download API
# ============================================================================

@app.route('/api/download/<file_type>/<filename>')
@login_required
@handle_errors
def download_file(file_type: str, filename: str):
    """Download a file"""
    if file_type not in ['textbooks', 'resources']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_type, filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(file_path, as_attachment=True)

# ============================================================================
# Dashboard Data API
# ============================================================================

@app.route('/api/dashboard-data')
@login_required
@handle_errors
def get_dashboard_data():
    """Get dashboard data based on user role"""
    if current_user.is_teacher:
        # Teacher dashboard data
        stats = {
            'notes': Note.query.filter_by(user_id=current_user.id).count(),
            'textbooks': Textbook.query.filter_by(uploaded_by=current_user.id).count(),
            'resources': Resource.query.filter_by(uploaded_by=current_user.id).count(),
            'students': User.query.filter_by(role='student').count(),
            'assignments': Assignment.query.filter_by(created_by=current_user.id).count()
        }
        
        recent_notes = Note.query.filter_by(user_id=current_user.id)\
            .order_by(Note.updated_at.desc()).limit(4).all()
        
        recent_resources = Resource.query.filter_by(uploaded_by=current_user.id)\
            .order_by(Resource.created_at.desc()).limit(4).all()
        
        return jsonify({
            'stats': stats,
            'recent_notes': [n.serialize for n in recent_notes],
            'recent_resources': [r.serialize for r in recent_resources]
        }), 200
        
    else:
        # Student dashboard data
        notes_count = Note.query.filter_by(user_id=current_user.id).count()
        textbooks_count = Textbook.query.count()
        resources_count = Resource.query.count()
        
        # Get pending assignments
        assignments = Assignment.query.all()
        submitted_ids = [s.assignment_id for s in Submission.query.filter_by(student_id=current_user.id).all()]
        pending_count = len([a for a in assignments if a.id not in submitted_ids])
        
        personal_notes = Note.query.filter_by(user_id=current_user.id)\
            .order_by(Note.updated_at.desc()).limit(4).all()
        
        teacher_notes = Note.query.filter_by(is_public=True, is_teacher_note=True)\
            .order_by(Note.updated_at.desc()).limit(4).all()
        
        return jsonify({
            'stats': {
                'notes': notes_count,
                'textbooks': textbooks_count,
                'resources': resources_count,
                'assignments': pending_count
            },
            'personal_notes': [n.serialize for n in personal_notes],
            'teacher_notes': [n.serialize for n in teacher_notes]
        }), 200

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 errors"""
    return jsonify({'error': 'Authentication required'}), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors"""
    return jsonify({'error': 'Access forbidden'}), 403

# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == '__main__':
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('RENDER') != 'true'
    
    logger.info("=" * 60)
    logger.info("StudyGrind Application Starting")
    logger.info(f"Environment: {'Production' if os.environ.get('RENDER') else 'Development'}")
    logger.info(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    logger.info("=" * 60)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
