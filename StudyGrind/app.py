import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, session
from flask_login import login_required, logout_user, current_user, LoginManager, login_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json

# Initialize Flask app
app = Flask(__name__, template_folder='templates')

# Use environment variables for sensitive data
app.secret_key = os.environ.get('SECRET_KEY', 'studygrind-secret-key-2024-very-secure')

# Configuration for production
app.config['SESSION_COOKIE_DOMAIN'] = None  # Will work with any domain
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DOMAIN'] = None
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

# Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'studygrind.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 
    'jpg', 'jpeg', 'png', 'gif', 'mp4', 'avi', 'mov'
}

# Initialize extensions
db = SQLAlchemy(app)

# CORS configuration - allow all origins for now (you can restrict later)
CORS(app, supports_credentials=True, origins=["http://localhost:5000", "http://127.0.0.1:5000"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'created_at': self.created_at.isoformat()
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
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
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
            'created_at': self.created_at.isoformat()
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
            'created_at': self.created_at.isoformat()
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
    
    creator = db.relationship('User', backref='assignments')
    
    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'instructions': self.instructions,
            'subject': self.subject,
            'max_score': self.max_score,
            'due_date': self.due_date.isoformat(),
            'created_by': self.created_by,
            'creator_name': self.creator.name if self.creator else '',
            'created_at': self.created_at.isoformat(),
            'days_remaining': (self.due_date - datetime.utcnow()).days if self.due_date else None
        }

class Submission(db.Model):
    __tablename__ = 'submissions'
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
    def serialize(self):
        return {
            'id': self.id,
            'assignment_id': self.assignment_id,
            'student_id': self.student_id,
            'student_name': self.student.name if self.student else '',
            'content': self.content,
            'filename': self.filename,
            'grade': self.grade,
            'feedback': self.feedback,
            'submitted_at': self.submitted_at.isoformat(),
            'graded_at': self.graded_at.isoformat() if self.graded_at else None,
            'assignment_title': self.assignment.title if self.assignment else ''
        }

class Event(db.Model):
    __tablename__ = 'events'
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
    def serialize(self):
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

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size(file):
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    return size

def create_upload_dirs():
    dirs = ['textbooks', 'resources', 'assignments', 'submissions']
    for dir_name in dirs:
        dir_path = os.path.join(app.config['UPLOAD_FOLDER'], dir_name)
        os.makedirs(dir_path, exist_ok=True)

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        create_upload_dirs()
        
        if not User.query.first():
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
            
            print("Default users created:")
            print("  Teacher: teacher@studygrind.com / teacher123")
            print("  Student: student@studygrind.com / student123")

# Routes
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        login_user(user, remember=True)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.serialize,
            'redirect': '/teacher' if user.role == 'teacher' else '/student'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        role = data.get('role', 'student')
        
        if not email or not password or not name:
            return jsonify({'error': 'All fields required'}), 400
        
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
        return jsonify({'error': str(e)}), 500

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

# API Routes
@app.route('/api/notes', methods=['GET'])
@login_required
def get_notes():
    try:
        notes = Note.query.filter_by(user_id=current_user.id).all()
        return jsonify({'notes': [note.serialize for note in notes]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/public', methods=['GET'])
@login_required
def get_public_notes():
    try:
        notes = Note.query.filter_by(is_public=True).all()
        return jsonify({'notes': [note.serialize for note in notes]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/<int:note_id>', methods=['GET'])
@login_required
def get_note(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        return jsonify({'note': note.serialize}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes', methods=['POST'])
@login_required
def create_note():
    try:
        data = request.get_json()
        note = Note(
            title=data.get('title'),
            content=data.get('content'),
            subject=data.get('subject'),
            tags=data.get('tags'),
            user_id=current_user.id,
            is_public=data.get('is_public', False),
            is_teacher_note=(current_user.role == 'teacher')
        )
        
        db.session.add(note)
        db.session.commit()
        
        return jsonify({'note': note.serialize, 'message': 'Note created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@login_required
def update_note(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        
        if note.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/textbooks', methods=['GET'])
@login_required
def get_textbooks():
    try:
        textbooks = Textbook.query.all()
        return jsonify({'textbooks': [tb.serialize for tb in textbooks]}), 200
    except Exception as e:
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
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks', filename)
        
        counter = 1
        base_name, ext = os.path.splitext(filename)
        while os.path.exists(file_path):
            filename = f"{base_name}_{counter}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks', filename)
            counter += 1
        
        file.save(file_path)
        
        textbook = Textbook(
            title=request.form.get('title', 'Untitled Textbook'),
            author=request.form.get('author', 'Unknown'),
            description=request.form.get('description', ''),
            subject=request.form.get('subject', 'General'),
            filename=filename,
            file_size=get_file_size(file),
            uploaded_by=current_user.id
        )
        
        db.session.add(textbook)
        db.session.commit()
        
        return jsonify({'textbook': textbook.serialize, 'message': 'Textbook uploaded successfully'}), 201
    except Exception as e:
        db.session.rollback()
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
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'textbooks', textbook.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(textbook)
        db.session.commit()
        
        return jsonify({'message': 'Textbook deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/resources', methods=['GET'])
@login_required
def get_resources():
    try:
        resources = Resource.query.all()
        return jsonify({'resources': [r.serialize for r in resources]}), 200
    except Exception as e:
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
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', filename)
        
        counter = 1
        base_name, ext = os.path.splitext(filename)
        while os.path.exists(file_path):
            filename = f"{base_name}_{counter}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', filename)
            counter += 1
        
        file.save(file_path)
        
        resource = Resource(
            title=request.form.get('title', 'Untitled Resource'),
            description=request.form.get('description', ''),
            resource_type=request.form.get('resource_type', 'other'),
            subject=request.form.get('subject', 'General'),
            filename=filename,
            file_size=get_file_size(file),
            uploaded_by=current_user.id
        )
        
        db.session.add(resource)
        db.session.commit()
        
        return jsonify({'resource': resource.serialize, 'message': 'Resource uploaded successfully'}), 201
    except Exception as e:
        db.session.rollback()
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
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', resource.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(resource)
        db.session.commit()
        
        return jsonify({'message': 'Resource deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments', methods=['GET'])
@login_required
def get_assignments():
    try:
        assignments = Assignment.query.all()
        return jsonify({'assignments': [a.serialize for a in assignments]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    try:
        assignment = Assignment.query.get_or_404(assignment_id)
        return jsonify({'assignment': assignment.serialize}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments', methods=['POST'])
@login_required
def create_assignment():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can create assignments'}), 403
        
        data = request.get_json()
        
        assignment = Assignment(
            title=data.get('title'),
            description=data.get('description'),
            instructions=data.get('instructions'),
            subject=data.get('subject', 'General'),
            max_score=data.get('max_score', 100),
            due_date=datetime.fromisoformat(data.get('due_date').replace('Z', '+00:00')),
            created_by=current_user.id
        )
        
        db.session.add(assignment)
        db.session.commit()
        
        return jsonify({'assignment': assignment.serialize, 'message': 'Assignment created successfully'}), 201
    except Exception as e:
        db.session.rollback()
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions', methods=['POST'])
@login_required
def submit_assignment():
    try:
        if current_user.role != 'student':
            return jsonify({'error': 'Only students can submit assignments'}), 403
        
        data = request.get_json()
        
        submission = Submission(
            assignment_id=data.get('assignment_id'),
            student_id=current_user.id,
            content=data.get('content'),
            filename=data.get('filename')
        )
        
        db.session.add(submission)
        db.session.commit()
        
        return jsonify({'submission': submission.serialize, 'message': 'Assignment submitted successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions/<int:submission_id>/grade', methods=['POST'])
@login_required
def grade_submission(submission_id):
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Only teachers can grade submissions'}), 403
        
        submission = Submission.query.get_or_404(submission_id)
        data = request.get_json()
        
        if 'grade' in data:
            submission.grade = data.get('grade')
        if 'feedback' in data:
            submission.feedback = data.get('feedback')
        
        submission.graded_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'submission': submission.serialize, 'message': 'Submission graded successfully'}), 200
    except Exception as e:
        db.session.rollback()
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    try:
        events = Event.query.all()
        return jsonify({'events': [e.serialize for e in events]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    try:
        data = request.get_json()
        
        event = Event(
            title=data.get('title'),
            description=data.get('description'),
            event_type=data.get('event_type', 'class'),
            start_date=datetime.fromisoformat(data.get('start_date').replace('Z', '+00:00')),
            end_date=datetime.fromisoformat(data.get('end_date').replace('Z', '+00:00')) if data.get('end_date') else None,
            all_day=data.get('all_day', False),
            color=data.get('color', '#4caf50'),
            created_by=current_user.id
        )
        
        db.session.add(event)
        db.session.commit()
        
        return jsonify({'event': event.serialize, 'message': 'Event created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/students', methods=['GET'])
@login_required
def get_students():
    try:
        if current_user.role != 'teacher':
            return jsonify({'error': 'Unauthorized'}), 403
        
        students = User.query.filter_by(role='student').all()
        return jsonify({'students': [s.serialize for s in students]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<file_type>/<filename>')
@login_required
def download_file(file_type, filename):
    try:
        if file_type not in ['textbooks', 'resources']:
            return jsonify({'error': 'Invalid file type'}), 400
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_type, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard-data')
@login_required
def get_dashboard_data():
    try:
        if current_user.role == 'teacher':
            notes_count = Note.query.filter_by(user_id=current_user.id).count()
            textbooks_count = Textbook.query.filter_by(uploaded_by=current_user.id).count()
            resources_count = Resource.query.filter_by(uploaded_by=current_user.id).count()
            students_count = User.query.filter_by(role='student').count()
            assignments_count = Assignment.query.filter_by(created_by=current_user.id).count()
            
            recent_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).limit(4).all()
            recent_resources = Resource.query.filter_by(uploaded_by=current_user.id).order_by(Resource.created_at.desc()).limit(4).all()
            
            return jsonify({
                'stats': {
                    'notes': notes_count,
                    'textbooks': textbooks_count,
                    'resources': resources_count,
                    'students': students_count,
                    'assignments': assignments_count
                },
                'recent_notes': [n.serialize for n in recent_notes],
                'recent_resources': [r.serialize for r in recent_resources]
            }), 200
            
        else:
            notes_count = Note.query.filter_by(user_id=current_user.id).count()
            textbooks_count = Textbook.query.count()
            resources_count = Resource.query.count()
            assignments = Assignment.query.all()
            
            submitted_assignments = [s.assignment_id for s in Submission.query.filter_by(student_id=current_user.id).all()]
            pending_assignments_count = len([a for a in assignments if a.id not in submitted_assignments])
            
            personal_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).limit(4).all()
            teacher_notes = Note.query.filter_by(is_public=True, is_teacher_note=True).order_by(Note.updated_at.desc()).limit(4).all()
            
            return jsonify({
                'stats': {
                    'notes': notes_count,
                    'textbooks': textbooks_count,
                    'resources': resources_count,
                    'assignments': pending_assignments_count
                },
                'personal_notes': [n.serialize for n in personal_notes],
                'teacher_notes': [n.serialize for n in teacher_notes]
            }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

# Run the application
# Replace the bottom of your app.py with:
if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("StudyGrind Application")
    print("=" * 60)
    # Only run in debug mode locally
    import os
    if os.environ.get('RENDER') != 'true':
        app.run(debug=True, port=5000)