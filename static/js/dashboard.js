// Global variables
let currentTimetableEntries = [];
let currentFilterDay = 'all';
let currentNote = null;
let currentQuiz = null;
let currentQuestionIndex = 0;
let answers = {};

// ==================== UTILITY FUNCTIONS ====================

function showSection(sectionId) {
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(section => section.classList.remove('active'));
    
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    const navItems = document.querySelectorAll('.sidebar-nav li');
    navItems.forEach(item => item.classList.remove('active'));
    
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
    
    // Save current section to localStorage
    localStorage.setItem('lastSection', sectionId);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    } catch (e) {
        return dateString;
    }
}

function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (e) {
        return dateString;
    }
}

// ==================== TIMETABLE FUNCTIONS ====================

async function loadTimetable() {
    try {
        const response = await fetch('/api/timetable');
        if (!response.ok) throw new Error('Failed to load timetable');
        const entries = await response.json();
        currentTimetableEntries = entries;
        renderTimetable();
    } catch (e) {
        console.error('Error loading timetable:', e);
        const container = document.getElementById('timetableContainer');
        if (container) {
            container.innerHTML = '<div class="empty-timetable">⚠️ Error loading timetable. Please refresh the page.</div>';
        }
    }
}

function renderTimetable() {
    const container = document.getElementById('timetableContainer');
    if (!container) return;
    
    const filteredEntries = currentFilterDay === 'all'
        ? currentTimetableEntries
        : currentTimetableEntries.filter(e => e.day_of_week === currentFilterDay);
    
    if (filteredEntries.length === 0) {
        container.innerHTML = '<div class="empty-timetable">📅 No timetable entries. Click "Add Entry" to create your schedule!</div>';
        return;
    }
    
    // Group by day
    const grouped = {};
    filteredEntries.forEach(entry => {
        if (!grouped[entry.day_of_week]) grouped[entry.day_of_week] = [];
        grouped[entry.day_of_week].push(entry);
    });
    
    const dayOrder = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    const sortedDays = Object.keys(grouped).sort((a, b) => dayOrder.indexOf(a) - dayOrder.indexOf(b));
    
    let html = '<table class="timetable-table"><thead><tr><th>Day</th><th>Schedule</th></tr></thead><tbody>';
    
    sortedDays.forEach(day => {
        const entries = grouped[day].sort((a, b) => a.start_time.localeCompare(b.start_time));
        html += `<tr><td style="width: 120px; font-weight: 700; vertical-align: top;">${escapeHtml(day)}</td><td>`;
        
        entries.forEach(entry => {
            html += `
                <div class="timetable-entry">
                    <strong>${escapeHtml(entry.subject)}</strong>
                    <small>${entry.start_time} - ${entry.end_time}</small>
                    ${entry.location ? `<div><i class="fa-solid fa-location-dot"></i> ${escapeHtml(entry.location)}</div>` : ''}
                    ${entry.notes ? `<div><small><i class="fa-solid fa-note-sticky"></i> ${escapeHtml(entry.notes)}</small></div>` : ''}
                    <div class="entry-actions">
                        <button class="edit-entry" onclick="editTimetableEntry(${entry.id})">
                            <i class="fa-solid fa-edit"></i> Edit
                        </button>
                        <button class="delete-entry" onclick="deleteTimetableEntry(${entry.id})">
                            <i class="fa-solid fa-trash"></i> Delete
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += `</td></tr>`;
    });
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

function filterTimetableByDay(day) {
    currentFilterDay = day;
    const filters = document.querySelectorAll('.day-filter');
    filters.forEach(btn => btn.classList.remove('active'));
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
    renderTimetable();
}

function openTimetableModal(entry = null) {
    const modal = document.getElementById('timetableModal');
    if (!modal) return;
    
    const form = document.getElementById('timetableForm');
    if (form) form.reset();
    
    if (entry) {
        document.getElementById('modalTitle').textContent = 'Edit Timetable Entry';
        document.getElementById('entryId').value = entry.id;
        document.getElementById('dayOfWeek').value = entry.day_of_week;
        document.getElementById('startTime').value = entry.start_time;
        document.getElementById('endTime').value = entry.end_time;
        document.getElementById('subject').value = entry.subject;
        document.getElementById('location').value = entry.location || '';
        document.getElementById('notes').value = entry.notes || '';
    } else {
        document.getElementById('modalTitle').textContent = 'Create Timetable Entry';
        document.getElementById('entryId').value = '';
    }
    
    modal.classList.add('active');
}

function closeTimetableModal() {
    const modal = document.getElementById('timetableModal');
    if (modal) modal.classList.remove('active');
}

async function editTimetableEntry(entryId) {
    const entry = currentTimetableEntries.find(e => e.id === entryId);
    if (entry) openTimetableModal(entry);
}

async function deleteTimetableEntry(entryId) {
    if (!confirm('Are you sure you want to delete this timetable entry?')) return;
    
    try {
        const response = await fetch(`/api/timetable/${entryId}`, { method: 'DELETE' });
        const data = await response.json();
        
        if (data.success) {
            alert('✓ Entry deleted successfully');
            loadTimetable();
        } else {
            alert('Error deleting entry: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Timetable form submission
const timetableForm = document.getElementById('timetableForm');
if (timetableForm) {
    timetableForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const entryId = document.getElementById('entryId').value;
        const data = {
            day_of_week: document.getElementById('dayOfWeek').value,
            start_time: document.getElementById('startTime').value,
            end_time: document.getElementById('endTime').value,
            subject: document.getElementById('subject').value,
            location: document.getElementById('location').value,
            notes: document.getElementById('notes').value
        };
        
        if (!data.day_of_week || !data.start_time || !data.end_time || !data.subject) {
            alert('Please fill in all required fields');
            return;
        }
        
        const url = entryId ? `/api/timetable/${entryId}` : '/api/timetable';
        const method = entryId ? 'PUT' : 'POST';
        
        try {
            const response = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                alert(entryId ? '✓ Entry updated successfully' : '✓ Entry created successfully');
                closeTimetableModal();
                loadTimetable();
            } else {
                alert('Error: ' + (result.error || 'Unknown error'));
            }
        } catch (e) {
            alert('Error: ' + e.message);
        }
    });
}

// ==================== NOTES FUNCTIONS ====================

async function loadNotes() {
    try {
        const response = await fetch('/api/notes');
        if (!response.ok) throw new Error('Failed to load notes');
        const notes = await response.json();
        const grid = document.getElementById('notesGrid');
        
        if (!grid) return;
        
        if (notes.length === 0) {
            grid.innerHTML = '<p style="text-align: center; color: var(--text-gray);">📚 No notes available yet. Check back later!</p>';
            return;
        }
        
        grid.innerHTML = notes.map(note => `
            <div class="note-card" onclick="viewNoteDetails(${note.id})">
                <div class="note-color" style="background: var(--blue);"></div>
                <h4>${escapeHtml(note.title)}</h4>
                <p><i class="fa-solid fa-book"></i> ${escapeHtml(note.subject || 'General')} • by ${escapeHtml(note.teacher || 'Teacher')}</p>
                <small><i class="fa-regular fa-calendar"></i> ${formatDate(note.created_at)}</small>
                ${note.file_path ? '<div style="margin-top: 8px;"><i class="fa-solid fa-paperclip"></i> Has attachment</div>' : ''}
            </div>
        `).join('');
    } catch (e) {
        console.error('Error loading notes:', e);
        const grid = document.getElementById('notesGrid');
        if (grid) grid.innerHTML = '<p style="color: red;">Error loading notes</p>';
    }
}

async function viewNoteDetails(noteId) {
    try {
        const response = await fetch(`/api/notes/${noteId}`);
        if (!response.ok) throw new Error('Failed to load note details');
        currentNote = await response.json();
        
        document.getElementById('noteTitle').textContent = currentNote.title;
        document.getElementById('noteSubject').textContent = currentNote.subject || 'General';
        document.getElementById('noteTeacher').textContent = currentNote.teacher;
        document.getElementById('noteDate').textContent = formatDate(currentNote.created_at);
        document.getElementById('noteDescription').innerHTML = currentNote.content || 'No description available.';
        
        const fileSection = document.getElementById('noteFileSection');
        if (currentNote.file_path) {
            fileSection.style.display = 'block';
        } else {
            fileSection.style.display = 'none';
        }
        
        const modal = document.getElementById('noteModal');
        if (modal) modal.classList.add('active');
    } catch (e) {
        console.error('Error loading note details:', e);
        alert('Error loading note details');
    }
}

function closeNoteModal() {
    const modal = document.getElementById('noteModal');
    if (modal) modal.classList.remove('active');
    currentNote = null;
}

function downloadNoteFile() {
    if (currentNote && currentNote.file_url) {
        window.open(currentNote.file_url, '_blank');
    } else {
        alert('No file attached to this note');
    }
}

async function uploadNote() {
    const title = document.getElementById('noteTitle')?.value;
    const subject = document.getElementById('noteSubject')?.value;
    const content = document.getElementById('noteContent')?.value;
    
    if (!title || !content) {
        alert('Please enter title and content');
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/api/notes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, subject, content })
        });
        
        if (response.ok) {
            alert('✓ Note uploaded successfully!');
            if (document.getElementById('noteTitle')) document.getElementById('noteTitle').value = '';
            if (document.getElementById('noteSubject')) document.getElementById('noteSubject').value = '';
            if (document.getElementById('noteContent')) document.getElementById('noteContent').value = '';
            loadNotes();
        } else {
            alert('Error uploading note');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// ==================== ASSIGNMENT FUNCTIONS ====================

async function loadAssignments() {
    try {
        const response = await fetch('/api/assignments');
        if (!response.ok) throw new Error('Failed to load assignments');
        const assignments = await response.json();
        const container = document.getElementById('assignmentsList');
        
        if (!container) return;
        
        if (assignments.length === 0) {
            container.innerHTML = '<div class="upload-container"><p>📋 No assignments yet.</p></div>';
            return;
        }
        
        container.innerHTML = assignments.map(ass => `
            <div class="upload-container" style="margin-bottom: 20px;">
                <h3>📝 ${escapeHtml(ass.title)}</h3>
                <p>${escapeHtml(ass.description)}</p>
                <p><strong>Due:</strong> ${formatDateTime(ass.due_date)}</p>
                <p><strong>Max Score:</strong> ${ass.max_score}</p>
                ${!ass.submitted ? `
                    <textarea id="submission-${ass.id}" placeholder="Write your submission here..." style="width:100%; margin:10px 0; padding:10px; border:2px solid var(--border); border-radius:12px;"></textarea>
                    <button class="btn-black-full" onclick="submitAssignment(${ass.id})">Submit Assignment</button>
                ` : '<p style="color: var(--yellow);">✓ Submitted</p>'}
            </div>
        `).join('');
    } catch (e) {
        console.error('Error loading assignments:', e);
    }
}

async function submitAssignment(assignmentId) {
    const content = document.getElementById(`submission-${assignmentId}`).value;
    
    if (!content) {
        alert('Please write your submission before submitting');
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';
    btn.disabled = true;
    
    try {
        const response = await fetch(`/api/assignments/${assignmentId}/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        
        if (response.ok) {
            alert('✓ Assignment submitted successfully!');
            loadAssignments();
            if (typeof loadStudentStats === 'function') loadStudentStats();
        } else {
            const error = await response.json();
            alert('Submission failed: ' + (error.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function publishAssignment() {
    const title = document.getElementById('assignTitle')?.value;
    const subject = document.getElementById('assignSubject')?.value;
    const dueDate = document.getElementById('assignDueDate')?.value;
    const description = document.getElementById('assignDesc')?.value;
    const maxScore = document.getElementById('assignMaxScore')?.value;
    
    if (!title || !dueDate) {
        alert('Please fill in title and due date');
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Publishing...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/api/assignments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, subject, due_date: dueDate, description, max_score: maxScore })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('✓ Assignment published successfully!');
            if (document.getElementById('assignTitle')) document.getElementById('assignTitle').value = '';
            if (document.getElementById('assignDesc')) document.getElementById('assignDesc').value = '';
            if (typeof loadTeacherStats === 'function') loadTeacherStats();
        } else {
            alert('Error publishing assignment');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// ==================== QUIZ FUNCTIONS ====================

async function loadQuizzes() {
    try {
        const response = await fetch('/api/quizzes');
        if (!response.ok) throw new Error('Failed to load quizzes');
        const quizzes = await response.json();
        const selector = document.getElementById('quizSelector');
        
        if (!selector) return;
        
        if (quizzes.length === 0) {
            selector.innerHTML = '<p>No quizzes available.</p>';
            return;
        }
        
        selector.innerHTML = `
            <select id="quizSelect" onchange="selectQuiz(this.value)" style="width:100%; padding:15px; margin-bottom:20px; border-radius:12px; border:2px solid var(--border);">
                <option value="">-- Select a quiz to take --</option>
                ${quizzes.map(q => `<option value="${q.id}" ${q.attempted ? 'disabled' : ''}>${escapeHtml(q.title)} (${q.subject}) - ${q.question_count} questions${q.attempted ? ' ✓ Completed' : ''}</option>`).join('')}
            </select>
            <div id="quizQuestions"></div>
        `;
    } catch (e) {
        console.error('Error loading quizzes:', e);
    }
}

async function selectQuiz(quizId) {
    if (!quizId) return;
    
    try {
        const response = await fetch(`/api/quizzes/${quizId}/take`);
        if (!response.ok) throw new Error('Failed to load quiz');
        currentQuiz = await response.json();
        currentQuestionIndex = 0;
        answers = {};
        displayQuestion();
    } catch (e) {
        alert('Error loading quiz: ' + e.message);
    }
}

function displayQuestion() {
    if (!currentQuiz || currentQuestionIndex >= currentQuiz.questions.length) {
        if (currentQuiz && currentQuiz.questions.length > 0) submitQuiz();
        return;
    }
    
    const q = currentQuiz.questions[currentQuestionIndex];
    const countDisplay = document.getElementById('quizCountDisplay');
    const progressBar = document.getElementById('quizProgress');
    
    if (countDisplay) countDisplay.innerHTML = `Question ${currentQuestionIndex + 1} of ${currentQuiz.questions.length}`;
    if (progressBar) progressBar.style.width = `${((currentQuestionIndex + 1) / currentQuiz.questions.length) * 100}%`;
    
    const container = document.getElementById('quizQuestions');
    if (!container) return;
    
    container.innerHTML = `
        <h2 class="q-text">${escapeHtml(q.text)}</h2>
        <div class="options">
            ${['A', 'B', 'C', 'D'].map(letter => `
                <div class="opt ${answers[q.id] === letter ? 'selected' : ''}" onclick="selectAnswer(${q.id}, '${letter}')">
                    ${letter}. ${escapeHtml(q.options[letter.charCodeAt(0) - 65])}
                </div>
            `).join('')}
        </div>
        <button class="btn-yellow-full" onclick="nextQuestion()">${currentQuestionIndex === currentQuiz.questions.length - 1 ? 'Submit Quiz' : 'Next Question'}</button>
    `;
}

function selectAnswer(questionId, answer) {
    answers[questionId] = answer;
    const opts = document.querySelectorAll('.opt');
    opts.forEach(opt => opt.classList.remove('selected'));
    if (event && event.currentTarget) event.currentTarget.classList.add('selected');
}

function nextQuestion() {
    currentQuestionIndex++;
    displayQuestion();
}

async function submitQuiz() {
    try {
        const response = await fetch(`/api/quizzes/${currentQuiz.id}/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ answers })
        });
        
        const result = await response.json();
        alert(`🎉 Quiz completed! Your score: ${result.score.toFixed(1)}%`);
        loadQuizzes();
        if (typeof loadStudentStats === 'function') loadStudentStats();
        
        const questionsDiv = document.getElementById('quizQuestions');
        if (questionsDiv) questionsDiv.innerHTML = '<p style="text-align:center;">✓ Quiz submitted! Select another quiz to continue.</p>';
        
        const quizSelect = document.getElementById('quizSelect');
        if (quizSelect) quizSelect.value = '';
    } catch (e) {
        alert('Error submitting quiz: ' + e.message);
    }
}

function setCorrect(element) {
    const rows = element.parentElement.querySelectorAll('.mcq-row');
    rows.forEach(row => row.classList.remove('active'));
    element.classList.add('active');
}

async function publishQuestion() {
    const title = document.getElementById('quizTitle')?.value;
    const subject = document.getElementById('quizSubject')?.value;
    const questionText = document.getElementById('qText')?.value;
    const optA = document.getElementById('optA')?.value;
    const optB = document.getElementById('optB')?.value;
    const optC = document.getElementById('optC')?.value;
    const optD = document.getElementById('optD')?.value;
    
    let correctAnswer = 'A';
    const rows = document.querySelectorAll('.mcq-row');
    rows.forEach((row, idx) => {
        if (row.classList.contains('active')) correctAnswer = String.fromCharCode(65 + idx);
    });
    
    if (!title || !questionText) {
        alert('Please fill in quiz title and question');
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Adding...';
    btn.disabled = true;
    
    try {
        const quizResponse = await fetch('/api/quizzes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, subject, description: questionText })
        });
        
        const quizData = await quizResponse.json();
        
        if (quizData.success) {
            await fetch(`/api/quizzes/${quizData.id}/questions`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: questionText,
                    option_a: optA,
                    option_b: optB,
                    option_c: optC,
                    option_d: optD,
                    correct_answer: correctAnswer
                })
            });
            
            alert('✓ Question added successfully!');
            if (document.getElementById('qText')) document.getElementById('qText').value = '';
            if (document.getElementById('optA')) document.getElementById('optA').value = '';
            if (document.getElementById('optB')) document.getElementById('optB').value = '';
            if (document.getElementById('optC')) document.getElementById('optC').value = '';
            if (document.getElementById('optD')) document.getElementById('optD').value = '';
            if (typeof loadTeacherStats === 'function') loadTeacherStats();
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// ==================== STUDENT FUNCTIONS ====================

async function loadStudentStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to load stats');
        const stats = await response.json();
        
        const pendingEl = document.getElementById('pendingCount');
        const avgEl = document.getElementById('avgScore');
        const quizEl = document.getElementById('quizCount');
        const statsEl = document.getElementById('studentStats');
        
        if (pendingEl) pendingEl.textContent = stats.pending_assignments || 0;
        if (avgEl) avgEl.textContent = Math.round(stats.avg_score || 0) + '%';
        if (quizEl) quizEl.textContent = stats.completed_quizzes || 0;
        if (statsEl) statsEl.innerHTML = `You have ${stats.pending_assignments || 0} pending assignments and ${stats.completed_quizzes || 0} completed quizzes.`;
    } catch (e) {
        console.error('Error loading student stats:', e);
    }
}

// ==================== TEACHER FUNCTIONS ====================

async function loadTeacherStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to load stats');
        const stats = await response.json();
        
        const assignmentsEl = document.getElementById('assignmentsCount');
        const quizzesEl = document.getElementById('quizzesCount');
        const submissionsEl = document.getElementById('submissionsCount');
        const studentsEl = document.getElementById('studentsCount');
        const statsEl = document.getElementById('teacherStats');
        
        if (assignmentsEl) assignmentsEl.textContent = stats.assignments || 0;
        if (quizzesEl) quizzesEl.textContent = stats.quizzes || 0;
        if (submissionsEl) submissionsEl.textContent = stats.submissions || 0;
        if (studentsEl) studentsEl.textContent = stats.students || 0;
        if (statsEl) statsEl.innerHTML = `You have ${stats.submissions || 0} pending submissions to grade`;
    } catch (e) {
        console.error('Error loading teacher stats:', e);
    }
}

async function loadSubmissions() {
    try {
        const response = await fetch('/api/submissions');
        if (!response.ok) throw new Error('Failed to load submissions');
        const submissions = await response.json();
        const tbody = document.getElementById('submissionsList');
        
        if (!tbody) return;
        
        if (submissions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5">No submissions yet</td></tr>';
            return;
        }
        
        const pendingSubmissions = submissions.filter(s => !s.graded);
        tbody.innerHTML = pendingSubmissions.map(sub => `
            <tr>
                <td>${escapeHtml(sub.student)}</td>
                <td>${escapeHtml(sub.assignment_title)}</td>
                <td>${formatDateTime(sub.submitted_at)}</td>
                <td><input type="number" class="score-input" id="score-${sub.id}" placeholder="Score"></td>
                <td><button class="btn-save" onclick="gradeSubmission(${sub.id})">Save Grade</button></td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Error loading submissions:', e);
    }
}

async function gradeSubmission(submissionId) {
    const scoreInput = document.getElementById(`score-${submissionId}`);
    const score = scoreInput.value;
    
    if (score === "" || score < 0 || score > 100) {
        alert("Please enter a valid score between 0 and 100");
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
    btn.disabled = true;
    
    try {
        const response = await fetch(`/api/submissions/${submissionId}/grade`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ score: parseFloat(score) })
        });
        
        if (response.ok) {
            alert('✓ Grade saved successfully!');
            loadSubmissions();
            if (typeof loadTeacherStats === 'function') loadTeacherStats();
        } else {
            alert('Error saving grade');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function loadPendingGrading() {
    try {
        const response = await fetch('/api/submissions');
        if (!response.ok) throw new Error('Failed to load submissions');
        const submissions = await response.json();
        const pending = submissions.filter(s => !s.graded);
        const container = document.getElementById('pendingGrading');
        
        if (!container) return;
        
        if (pending.length === 0) {
            container.innerHTML = '<li>No pending submissions</li>';
            return;
        }
        
        container.innerHTML = pending.slice(0, 5).map(s => `
            <li>
                <div>
                    <span class="item-title">${escapeHtml(s.student)} - ${escapeHtml(s.assignment_title)}</span>
                    <div class="item-date">Submitted: ${formatDate(s.submitted_at)}</div>
                </div>
                <span class="item-status status-pending">Pending</span>
            </li>
        `).join('');
    } catch (e) {
        console.error('Error loading pending grading:', e);
    }
}

// ==================== ADMIN FUNCTIONS ====================

async function loadAdminStats() {
    try {
        const [teachersRes, studentsRes, assignmentsRes, quizzesRes] = await Promise.all([
            fetch('/api/teachers'),
            fetch('/api/students'),
            fetch('/api/assignments'),
            fetch('/api/quizzes')
        ]);
        
        const teachers = await teachersRes.json();
        const students = await studentsRes.json();
        const assignments = await assignmentsRes.json();
        const quizzes = await quizzesRes.json();
        
        const teacherEl = document.getElementById('teacherCount');
        const studentEl = document.getElementById('studentCount');
        const assignmentEl = document.getElementById('assignmentCount');
        const quizEl = document.getElementById('quizCount');
        const statsEl = document.getElementById('adminStats');
        
        if (teacherEl) teacherEl.textContent = teachers.length;
        if (studentEl) studentEl.textContent = students.length;
        if (assignmentEl) assignmentEl.textContent = assignments.length;
        if (quizEl) quizEl.textContent = quizzes.length;
        if (statsEl) statsEl.innerHTML = `Managing ${teachers.length} teachers and ${students.length} students`;
    } catch (e) {
        console.error('Error loading admin stats:', e);
    }
}

async function loadTeachers() {
    try {
        const response = await fetch('/api/teachers');
        if (!response.ok) throw new Error('Failed to load teachers');
        const teachers = await response.json();
        const tbody = document.getElementById('teachersList');
        
        if (!tbody) return;
        
        if (teachers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3">No teachers yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = teachers.map(t => `
            <tr>
                <td>${escapeHtml(t.full_name)}</td>
                <td>${escapeHtml(t.email)}</td>
                <td>${formatDate(t.created_at)}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Error loading teachers:', e);
    }
}

async function loadStudents() {
    try {
        const response = await fetch('/api/students');
        if (!response.ok) throw new Error('Failed to load students');
        const students = await response.json();
        const tbody = document.getElementById('studentsList');
        
        if (!tbody) return;
        
        if (students.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3">No students yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = students.map(s => `
            <tr>
                <td>${escapeHtml(s.full_name)}</td>
                <td>${escapeHtml(s.email)}</td>
                <td><span style="color: #22c55e;">● Active</span></td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Error loading students:', e);
    }
}

async function addTeacher() {
    const full_name = document.getElementById('teacherName')?.value;
    const email = document.getElementById('teacherEmail')?.value;
    const username = document.getElementById('teacherUsername')?.value;
    
    if (!full_name || !email || !username) {
        alert('Please fill all fields');
        return;
    }
    
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Adding...';
    btn.disabled = true;
    
    try {
        const response = await fetch('/api/teachers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name, email, username, password: 'password123' })
        });
        
        if (response.ok) {
            alert('✓ Teacher added successfully! Default password: password123');
            if (document.getElementById('teacherName')) document.getElementById('teacherName').value = '';
            if (document.getElementById('teacherEmail')) document.getElementById('teacherEmail').value = '';
            if (document.getElementById('teacherUsername')) document.getElementById('teacherUsername').value = '';
            loadTeachers();
            loadAdminStats();
        } else {
            alert('Error adding teacher');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function saveSettings() {
    alert('Settings saved successfully!');
}

// ==================== INITIALIZATION ====================

// Close modals when clicking outside
window.onclick = function(event) {
    const timetableModal = document.getElementById('timetableModal');
    const noteModal = document.getElementById('noteModal');
    
    if (event.target === timetableModal) closeTimetableModal();
    if (event.target === noteModal) closeNoteModal();
};

// Search functionality
const searchInput = document.getElementById('searchInput');
if (searchInput) {
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const notes = document.querySelectorAll('.note-card');
        notes.forEach(note => {
            const text = note.textContent.toLowerCase();
            note.style.display = text.includes(searchTerm) ? 'block' : 'none';
        });
    });
}

// Initialize based on role
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    
    // Restore last active section
    const lastSection = localStorage.getItem('lastSection');
    if (lastSection && document.getElementById(lastSection)) {
        showSection(lastSection);
    }
    
    if (path.includes('/student')) {
        loadStudentStats();
        loadTimetable();
        loadNotes();
        loadAssignments();
        loadQuizzes();
    } else if (path.includes('/teacher')) {
        loadTeacherStats();
        loadTimetable();
        loadAssignments();
        loadSubmissions();
        loadNotes();
        loadPendingGrading();
    } else if (path.includes('/admin')) {
        loadAdminStats();
        loadTeachers();
        loadStudents();
        
        // Initialize charts if on admin page
        if (typeof Chart !== 'undefined') {
            const ctx = document.getElementById('activityChart')?.getContext('2d');
            if (ctx) {
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                        datasets: [{
                            label: 'Active Users',
                            data: [45, 62, 78, 94],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }
            
            const pieCtx = document.getElementById('activityDistChart')?.getContext('2d');
            if (pieCtx) {
                new Chart(pieCtx, {
                    type: 'pie',
                    data: {
                        labels: ['Students', 'Teachers', 'Admins'],
                        datasets: [{
                            data: [75, 20, 5],
                            backgroundColor: ['#3b82f6', '#facc15', '#ef4444']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true
                    }
                });
            }
        }
    }
});

// ==================== LOGOUT FUNCTION ====================
window.logout = async function() {
    if (confirm('Are you sure you want to logout? This will clear your session.')) {
        try {
            // Show loading state
            const logoutBtn = event?.currentTarget;
            if (logoutBtn) {
                const originalText = logoutBtn.innerHTML;
                logoutBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Logging out...';
                logoutBtn.disabled = true;
            }
            
            // Clear all local storage
            localStorage.clear();
            
            // Clear all session storage
            sessionStorage.clear();
            
            // Clear any cookies
            document.cookie.split(";").forEach(function(c) {
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
            });
            
            // Call logout endpoint
            const response = await fetch('/auth/logout');
            
            // Force hard redirect without cache
            window.location.replace('/auth/login');
        } catch (error) {
            console.error('Logout error:', error);
            // Fallback redirect
            window.location.href = '/auth/logout';
        }
    }
};

// Also add a function for Google login with remember me option
function googleLoginWithRemember(rememberMe = false) {
    const url = `/auth/login/google?remember_me=${rememberMe}`;
    window.location.href = url;
}
