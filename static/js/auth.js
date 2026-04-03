// Authentication JavaScript for Login/Register pages

function showForm(formId) {
    const forms = document.querySelectorAll('.auth-box');
    forms.forEach(form => {
        form.classList.remove('active');
    });
    const targetForm = document.getElementById(formId);
    if (targetForm) {
        targetForm.classList.add('active');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe')?.checked || false;
    
    if (!email || !password) {
        alert('Please enter both email and password');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Signing in...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                email, 
                password,
                remember_me: rememberMe 
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store remember me preference
            if (rememberMe) {
                localStorage.setItem('rememberEmail', email);
            } else {
                localStorage.removeItem('rememberEmail');
            }
            window.location.href = data.redirect;
        } else {
            alert('Login failed: ' + (data.error || 'Invalid credentials'));
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please check your connection and try again.');
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

async function handleRegister(event) {
    event.preventDefault();
    
    const full_name = document.getElementById('regFullName').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    
    if (!full_name || !email || !password) {
        alert('Please fill in all fields');
        return;
    }
    
    if (password.length < 6) {
        alert('Password must be at least 6 characters long');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating account...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ full_name, email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Account created successfully! Redirecting to dashboard...');
            window.location.href = data.redirect;
        } else {
            alert('Registration failed: ' + (data.error || 'Please try again'));
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed. Please check your connection and try again.');
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

async function handleForgot(event) {
    event.preventDefault();
    
    const email = document.getElementById('resetEmail').value;
    
    if (!email) {
        alert('Please enter your email address');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending...';
    submitBtn.disabled = true;
    
    try {
        // Simulate API call - implement actual password reset endpoint
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        alert('If an account exists with this email, you will receive a password reset link.');
        showForm('login-form');
    } catch (error) {
        alert('Error sending reset link. Please try again.');
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

// Auto-fill remembered email on page load
document.addEventListener('DOMContentLoaded', () => {
    const rememberedEmail = localStorage.getItem('rememberEmail');
    if (rememberedEmail) {
        const emailInput = document.getElementById('loginEmail');
        if (emailInput) {
            emailInput.value = rememberedEmail;
            const rememberCheckbox = document.getElementById('rememberMe');
            if (rememberCheckbox) {
                rememberCheckbox.checked = true;
            }
        }
    }
});

// Attach event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const forgotForm = document.getElementById('forgotForm');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    if (forgotForm) {
        forgotForm.addEventListener('submit', handleForgot);
    }
});

// Check session on page load
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is returning from Google OAuth
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('logged_out') === 'true') {
        // Clear any remaining session data
        localStorage.clear();
        sessionStorage.clear();
    }
    
    // Set a flag to indicate this is a fresh page load
    sessionStorage.setItem('pageLoaded', Date.now().toString());
});

// Clean up on before unload (optional)
window.addEventListener('beforeunload', () => {
    // Don't clear everything, just mark that we're leaving
    sessionStorage.setItem('lastVisit', Date.now().toString());
});
