from flask import Blueprint, request, jsonify, current_app, send_from_directory
from flask_login import login_required, current_user
from models import db, Note, CalendarEvent, Assignment, Submission, Quiz, Question, QuizAttempt, QuizAnswer, User, Timetable
from datetime import datetime
import os
from werkzeug.utils import secure_filename

api_bp = Blueprint('api', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx', 'txt', 'jpg', 'png'}

# ==================== NOTES API ====================
@api_bp.route('/notes', methods=['GET'])
@login_required
def get_notes():
    if current_user.is_teacher() or current_user.is_admin():
        notes = Note.query.filter_by(teacher_id=current_user.id).all()
    else:
        notes = Note.query.all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'content': n.content,
        'subject': n.subject,
        'teacher': n.author.full_name,
        'created_at': n.created_at.isoformat(),
        'file_path': n.file_path,
        'file_url': f"/api/static/uploads/{n.file_path}" if n.file_path else None
    } for n in notes])

@api_bp.route('/notes/<int:note_id>', methods=['GET'])
@login_required
def get_note_details(note_id):
    note = Note.query.get_or_404(note_id)
    
    return jsonify({
        'id': note.id,
        'title': note.title,
        'content': note.content,
        'subject': note.subject,
        'teacher': note.author.full_name,
        'created_at': note.created_at.isoformat(),
        'file_path': note.file_path,
        'file_url': f"/api/static/uploads/{note.file_path}" if note.file_path else None
    })

@api_bp.route('/notes', methods=['POST'])
@login_required
def create_note():
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    note = Note(
        title=data.get('title'),
        content=data.get('content'),
        subject=data.get('subject'),
        teacher_id=current_user.id
    )
    db.session.add(note)
    db.session.commit()
    
    return jsonify({'success': True, 'id': note.id})

# ==================== ASSIGNMENTS API ====================
@api_bp.route('/assignments', methods=['GET'])
@login_required
def get_assignments():
    if current_user.is_teacher():
        assignments = Assignment.query.filter_by(teacher_id=current_user.id).all()
    else:
        assignments = Assignment.query.all()
    
    return jsonify([{
        'id': a.id,
        'title': a.title,
        'description': a.description,
        'subject': a.subject,
        'due_date': a.due_date.isoformat(),
        'max_score': a.max_score,
        'teacher': a.teacher.full_name,
        'submitted': any(s.student_id == current_user.id for s in a.submissions) if current_user.is_student() else None
    } for a in assignments])

@api_bp.route('/assignments', methods=['POST'])
@login_required
def create_assignment():
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    assignment = Assignment(
        title=data.get('title'),
        description=data.get('description'),
        subject=data.get('subject'),
        due_date=datetime.fromisoformat(data.get('due_date')),
        max_score=data.get('max_score', 100),
        teacher_id=current_user.id
    )
    db.session.add(assignment)
    db.session.commit()
    
    return jsonify({'success': True, 'id': assignment.id})

@api_bp.route('/assignments/<int:assignment_id>/submit', methods=['POST'])
@login_required
def submit_assignment(assignment_id):
    if not current_user.is_student():
        return jsonify({'error': 'Only students can submit assignments'}), 403
    
    assignment = Assignment.query.get_or_404(assignment_id)
    
    existing = Submission.query.filter_by(assignment_id=assignment_id, student_id=current_user.id).first()
    if existing:
        return jsonify({'error': 'Already submitted'}), 400
    
    data = request.get_json()
    submission = Submission(
        assignment_id=assignment_id,
        student_id=current_user.id,
        content=data.get('content'),
        file_path=data.get('file_path')
    )
    db.session.add(submission)
    db.session.commit()
    
    return jsonify({'success': True, 'id': submission.id})

@api_bp.route('/submissions', methods=['GET'])
@login_required
def get_submissions():
    if current_user.is_teacher():
        submissions = Submission.query.join(Assignment).filter(Assignment.teacher_id == current_user.id).all()
    else:
        submissions = Submission.query.filter_by(student_id=current_user.id).all()
    
    return jsonify([{
        'id': s.id,
        'assignment_title': s.assignment.title,
        'student': s.student.full_name,
        'score': s.score,
        'submitted_at': s.submitted_at.isoformat(),
        'graded': s.score is not None
    } for s in submissions])

@api_bp.route('/submissions/<int:submission_id>/grade', methods=['POST'])
@login_required
def grade_submission(submission_id):
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    submission = Submission.query.get_or_404(submission_id)
    data = request.get_json()
    
    submission.score = data.get('score')
    submission.feedback = data.get('feedback')
    submission.graded_at = datetime.utcnow()
    
    db.session.commit()
    return jsonify({'success': True})

# ==================== QUIZZES API ====================
@api_bp.route('/quizzes', methods=['GET'])
@login_required
def get_quizzes():
    if current_user.is_teacher():
        quizzes = Quiz.query.filter_by(teacher_id=current_user.id).all()
    else:
        quizzes = Quiz.query.all()
    
    return jsonify([{
        'id': q.id,
        'title': q.title,
        'description': q.description,
        'subject': q.subject,
        'time_limit': q.time_limit,
        'question_count': len(q.questions),
        'attempted': any(a.student_id == current_user.id for a in q.attempts) if current_user.is_student() else None
    } for q in quizzes])

@api_bp.route('/quizzes', methods=['POST'])
@login_required
def create_quiz():
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    quiz = Quiz(
        title=data.get('title'),
        description=data.get('description'),
        subject=data.get('subject'),
        time_limit=data.get('time_limit'),
        teacher_id=current_user.id
    )
    db.session.add(quiz)
    db.session.commit()
    
    return jsonify({'success': True, 'id': quiz.id})

@api_bp.route('/quizzes/<int:quiz_id>/questions', methods=['POST'])
@login_required
def add_question(quiz_id):
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    question = Question(
        quiz_id=quiz_id,
        text=data.get('text'),
        option_a=data.get('option_a'),
        option_b=data.get('option_b'),
        option_c=data.get('option_c'),
        option_d=data.get('option_d'),
        correct_answer=data.get('correct_answer'),
        points=data.get('points', 1)
    )
    db.session.add(question)
    db.session.commit()
    
    return jsonify({'success': True, 'id': question.id})

@api_bp.route('/quizzes/<int:quiz_id>/take', methods=['GET'])
@login_required
def take_quiz(quiz_id):
    if not current_user.is_student():
        return jsonify({'error': 'Only students can take quizzes'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    return jsonify({
        'id': quiz.id,
        'title': quiz.title,
        'description': quiz.description,
        'time_limit': quiz.time_limit,
        'questions': [{
            'id': q.id,
            'text': q.text,
            'options': [q.option_a, q.option_b, q.option_c, q.option_d]
        } for q in quiz.questions]
    })

@api_bp.route('/quizzes/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    if not current_user.is_student():
        return jsonify({'error': 'Only students can submit quizzes'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    data = request.get_json()
    answers = data.get('answers', {})
    
    attempt = QuizAttempt(
        quiz_id=quiz_id,
        student_id=current_user.id,
        completed_at=datetime.utcnow()
    )
    db.session.add(attempt)
    db.session.flush()
    
    total_points = 0
    earned_points = 0
    
    for question in quiz.questions:
        selected = answers.get(str(question.id))
        is_correct = (selected == question.correct_answer)
        
        answer = QuizAnswer(
            attempt_id=attempt.id,
            question_id=question.id,
            selected_answer=selected or '',
            is_correct=is_correct
        )
        db.session.add(answer)
        
        total_points += question.points
        if is_correct:
            earned_points += question.points
    
    attempt.score = (earned_points / total_points * 100) if total_points > 0 else 0
    db.session.commit()
    
    return jsonify({'success': True, 'score': attempt.score})

# ==================== TEACHERS API ====================
@api_bp.route('/teachers', methods=['GET'])
@login_required
def get_teachers():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    teachers = User.query.filter_by(role='teacher').all()
    return jsonify([{
        'id': t.id,
        'full_name': t.full_name,
        'email': t.email,
        'username': t.username,
        'created_at': t.created_at.isoformat()
    } for t in teachers])

@api_bp.route('/teachers', methods=['POST'])
@login_required
def add_teacher():
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    teacher = User(
        username=data.get('username'),
        email=data.get('email'),
        role='teacher',
        full_name=data.get('full_name')
    )
    teacher.set_password(data.get('password', 'password123'))
    
    db.session.add(teacher)
    db.session.commit()
    
    return jsonify({'success': True, 'id': teacher.id})

@api_bp.route('/students', methods=['GET'])
@login_required
def get_students():
    if not (current_user.is_teacher() or current_user.is_admin()):
        return jsonify({'error': 'Unauthorized'}), 403
    
    students = User.query.filter_by(role='student').all()
    return jsonify([{
        'id': s.id,
        'full_name': s.full_name,
        'email': s.email
    } for s in students])

# ==================== STATS API ====================
@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    if current_user.is_teacher():
        assignments = Assignment.query.filter_by(teacher_id=current_user.id).count()
        quizzes = Quiz.query.filter_by(teacher_id=current_user.id).count()
        notes = Note.query.filter_by(teacher_id=current_user.id).count()
        submissions = Submission.query.join(Assignment).filter(Assignment.teacher_id == current_user.id).count()
        
        return jsonify({
            'assignments': assignments,
            'quizzes': quizzes,
            'notes': notes,
            'submissions': submissions,
            'students': User.query.filter_by(role='student').count()
        })
    elif current_user.is_student():
        pending_assignments = Assignment.query.filter(
            ~Assignment.submissions.any(student_id=current_user.id)
        ).count()
        
        return jsonify({
            'pending_assignments': pending_assignments,
            'completed_quizzes': QuizAttempt.query.filter_by(student_id=current_user.id).count(),
            'avg_score': db.session.query(db.func.avg(QuizAttempt.score)).filter_by(student_id=current_user.id).scalar() or 0
        })
    
    return jsonify({})

# ==================== TIMETABLE API ====================
@api_bp.route('/timetable', methods=['GET'])
@login_required
def get_timetable():
    if not current_user.is_student():
        return jsonify({'error': 'Only students can access timetable'}), 403
    
    entries = Timetable.query.filter_by(student_id=current_user.id).all()
    
    return jsonify([{
        'id': e.id,
        'day_of_week': e.day_of_week,
        'start_time': e.start_time,
        'end_time': e.end_time,
        'subject': e.subject,
        'location': e.location,
        'notes': e.notes,
        'created_at': e.created_at.isoformat()
    } for e in entries])

@api_bp.route('/timetable', methods=['POST'])
@login_required
def create_timetable_entry():
    if not current_user.is_student():
        return jsonify({'error': 'Only students can create timetable entries'}), 403
    
    data = request.get_json()
    
    required_fields = ['day_of_week', 'start_time', 'end_time', 'subject']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    entry = Timetable(
        student_id=current_user.id,
        day_of_week=data.get('day_of_week'),
        start_time=data.get('start_time'),
        end_time=data.get('end_time'),
        subject=data.get('subject'),
        location=data.get('location'),
        notes=data.get('notes')
    )
    
    db.session.add(entry)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'id': entry.id,
        'message': 'Timetable entry created successfully'
    })

@api_bp.route('/timetable/<int:entry_id>', methods=['PUT'])
@login_required
def update_timetable_entry(entry_id):
    if not current_user.is_student():
        return jsonify({'error': 'Only students can update timetable entries'}), 403
    
    entry = Timetable.query.get_or_404(entry_id)
    
    if entry.student_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    if 'day_of_week' in data:
        entry.day_of_week = data['day_of_week']
    if 'start_time' in data:
        entry.start_time = data['start_time']
    if 'end_time' in data:
        entry.end_time = data['end_time']
    if 'subject' in data:
        entry.subject = data['subject']
    if 'location' in data:
        entry.location = data['location']
    if 'notes' in data:
        entry.notes = data['notes']
    
    entry.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Timetable entry updated successfully'
    })

@api_bp.route('/timetable/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_timetable_entry(entry_id):
    if not current_user.is_student():
        return jsonify({'error': 'Only students can delete timetable entries'}), 403
    
    entry = Timetable.query.get_or_404(entry_id)
    
    if entry.student_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(entry)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Timetable entry deleted successfully'
    })

# ==================== FILE SERVING ====================
@api_bp.route('/static/uploads/<filename>')
@login_required
def serve_uploaded_file(filename):
    upload_dir = os.path.join(current_app.root_path, 'static', 'uploads')
    return send_from_directory(upload_dir, filename)