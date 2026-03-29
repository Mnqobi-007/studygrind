// Authentication JavaScript

function showForm(formId) {
    document.querySelectorAll('.auth-box').forEach(form => {
        form.classList.remove('active');
    });
    document.getElementById(formId).classList.add('active');
}

async function handleLogin(event) {
    event.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (data.success) {
            window.location.href = data.redirect;
        } else {
            alert('Login failed: ' + (data.error || 'Invalid credentials'));
        }
    } catch (error) {
        alert('Login failed. Please try again.');
    }
}

async function handleRegister(event) {
    event.preventDefault();
    const full_name = document.getElementById('regFullName').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;

    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name, email, password })
        });

        const data = await response.json();
        if (data.success) {
            window.location.href = data.redirect;
        } else {
            alert('Registration failed: ' + (data.error || 'Please try again'));
        }
    } catch (error) {
        alert('Registration failed. Please try again.');
    }
}

async function handleForgot(event) {
    event.preventDefault();
    alert('Password reset link would be sent to your email. This feature is coming soon.');
}

// Attach event listeners
document.getElementById('loginForm')?.addEventListener('submit', handleLogin);
document.getElementById('registerForm')?.addEventListener('submit', handleRegister);
document.getElementById('forgotForm')?.addEventListener('submit', handleForgot);