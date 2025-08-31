// PathStarter Job Board - Enhanced Interactive Experience
document.addEventListener('DOMContentLoaded', () => {
    console.log('PathStarter job board loaded successfully!');
    
    // Track page views
    trackEvent('page_view', {
        page: window.location.pathname,
        timestamp: new Date().toISOString()
    });

    // Initialize all components
    initializeNavigation();
    initializeJobFilters();
    initializeSearch();
    initializeAnimations();
    initializeAuthForms();
    checkAuthStatus();
});

// Enhanced Navigation with smooth animations
function initializeNavigation() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('nav-menu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
            
            // Add stagger animation to menu items
            const menuItems = navMenu.querySelectorAll('.nav-link');
            menuItems.forEach((item, index) => {
                if (navMenu.classList.contains('active')) {
                    item.style.animationDelay = `${index * 0.1}s`;
                    item.style.animation = 'slideInLeft 0.3s ease forwards';
                } else {
                    item.style.animation = '';
                }
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!hamburger.contains(e.target) && !navMenu.contains(e.target)) {
                hamburger.classList.remove('active');
                navMenu.classList.remove('active');
            }
        });
    }
    // Created by Afia Raisa – PathStarter Project
    // Unauthorized use without credit is discouraged
    // Enhanced navbar scroll effect
    let lastScrollY = window.scrollY;
    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        if (navbar) {
            if (window.scrollY > lastScrollY && window.scrollY > 100) {
                navbar.style.transform = 'translateY(-100%)';
            } else {
                navbar.style.transform = 'translateY(0)';
            }
            
            // Add background opacity based on scroll
            const opacity = Math.min(window.scrollY / 100, 1);
            navbar.style.backgroundColor = `rgba(10, 14, 26, ${0.95 * opacity})`;
        }
        lastScrollY = window.scrollY;
    });
}

// Enhanced Job Filtering with smooth transitions
function initializeJobFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const jobCards = document.querySelectorAll('.job-card');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const filter = btn.getAttribute('data-filter');
            
            // Update active button with animation
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Animate job cards
            jobCards.forEach((card, index) => {
                const category = card.getAttribute('data-category');
                
                if (filter === 'all' || category === filter) {
                    card.style.animation = 'none';
                    card.offsetHeight; // Trigger reflow
                    card.style.animation = `fadeInUp 0.6s ease ${index * 0.1}s forwards`;
                    card.style.display = 'block';
                } else {
                    card.style.animation = 'fadeOut 0.3s ease forwards';
                    setTimeout(() => {
                        card.style.display = 'none';
                    }, 300);
                }
            });
            
            trackEvent('filter_used', { filter });
        });
    });
}

// Enhanced Search with suggestions and history
function initializeSearch() {
    const searchInput = document.querySelector('.search-input');
    const searchBtn = document.querySelector('.search-btn');
    
    if (searchInput && searchBtn) {
        // Add search suggestions
        const suggestions = [
            'Software Developer', 'Data Scientist', 'UX Designer', 
            'Marketing Intern', 'Product Manager', 'Frontend Developer'
        ];
        
        // Create suggestions dropdown
        const suggestionsDropdown = document.createElement('div');
        suggestionsDropdown.className = 'search-suggestions';
        suggestionsDropdown.style.cssText = `
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0 0 8px 8px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        `;
        
        const searchContainer = searchInput.closest('.search-container') || searchInput.parentElement;
        searchContainer.style.position = 'relative';
        searchContainer.appendChild(suggestionsDropdown);
        
        searchInput.addEventListener('input', (e) => {
            const value = e.target.value.toLowerCase();
            if (value.length > 1) {
                const filtered = suggestions.filter(s => 
                    s.toLowerCase().includes(value)
                );
                
                if (filtered.length > 0) {
                    suggestionsDropdown.innerHTML = filtered.map(suggestion => 
                        `<div class="suggestion-item" style="padding: 12px; cursor: pointer; transition: background 0.2s;">${suggestion}</div>`
                    ).join('');
                    suggestionsDropdown.style.display = 'block';
                    
                    // Add click handlers to suggestions
                    suggestionsDropdown.querySelectorAll('.suggestion-item').forEach(item => {
                        item.addEventListener('click', () => {
                            searchInput.value = item.textContent;
                            suggestionsDropdown.style.display = 'none';
                            performSearch(item.textContent);
                        });
                        
                        item.addEventListener('mouseenter', () => {
                            item.style.background = 'var(--glassmorphism)';
                        });
                        
                        item.addEventListener('mouseleave', () => {
                            item.style.background = 'transparent';
                        });
                    });
                } else {
                    suggestionsDropdown.style.display = 'none';
                }
            } else {
                suggestionsDropdown.style.display = 'none';
            }
        });
        
        // Hide suggestions when clicking outside
        document.addEventListener('click', (e) => {
            if (!searchContainer.contains(e.target)) {
                suggestionsDropdown.style.display = 'none';
            }
        });
        
        searchBtn.addEventListener('click', () => {
            performSearch(searchInput.value);
        });
        
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                performSearch(searchInput.value);
            }
        });
    }
}

function performSearch(query) {
    if (query.trim()) {
        console.log('Searching for:', query);
        trackEvent('search_performed', { query });
        showNotification(`Searching for "${query}"...`, 'info');
        
        // Simulate search loading
        setTimeout(() => {
            showNotification(`Found results for "${query}"`, 'success');
        }, 1500);
    }
}

// Enhanced Animations and Scroll Effects
function initializeAnimations() {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'fadeInUp 0.8s ease forwards';
                entry.target.style.opacity = '1';
            }
        });
    }, observerOptions);
    
    // Observe elements for animation
    const animateElements = document.querySelectorAll('.job-card, .benefit-card, .resource-card, .company-card');
    animateElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.animationDelay = `${index * 0.1}s`;
        observer.observe(el);
    });
    
    // Enhanced button interactions
    const buttons = document.querySelectorAll('button, .btn-primary, .btn-secondary');
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', () => {
            btn.style.transform = 'translateY(-2px)';
        });
        
        btn.addEventListener('mouseleave', () => {
            btn.style.transform = 'translateY(0)';
        });
        
        btn.addEventListener('click', (e) => {
            // Create ripple effect
            const ripple = document.createElement('span');
            const rect = btn.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${x}px;
                top: ${y}px;
                background: rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                transform: scale(0);
                animation: ripple 0.6s linear;
                pointer-events: none;
            `;
            
            btn.style.position = 'relative';
            btn.style.overflow = 'hidden';
            btn.appendChild(ripple);
            
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });
}

// Enhanced Authentication Forms
function initializeAuthForms() {
    // Password strength indicator
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        if (input.id === 'password' || input.name === 'password') {
            const strengthBar = document.createElement('div');
            strengthBar.className = 'password-strength';
            strengthBar.innerHTML = `
                <div class="strength-bar">
                    <div class="strength-fill"></div>
                </div>
                <div class="strength-text">Password strength</div>
            `;
            input.parentElement.appendChild(strengthBar);
            
            input.addEventListener('input', () => {
                const strength = calculatePasswordStrength(input.value);
                const fill = strengthBar.querySelector('.strength-fill');
                const text = strengthBar.querySelector('.strength-text');
                
                fill.style.width = `${strength.score * 25}%`;
                fill.style.background = strength.color;
                text.textContent = strength.text;
            });
        }
    });
    
    // Form validation with enhanced UX
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input[required]');
        
        inputs.forEach(input => {
            input.addEventListener('blur', () => {
                validateInput(input);
            });
            
            input.addEventListener('input', () => {
                if (input.classList.contains('invalid')) {
                    validateInput(input);
                }
            });
        });
        
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            
            let isValid = true;
            inputs.forEach(input => {
                if (!validateInput(input)) {
                    isValid = false;
                }
            });
            
            if (isValid) {
                handleFormSubmission(form);
            } else {
                showNotification('Please fix the errors in the form', 'error');
            }
        });
    });
}

function calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    const colors = ['#ff4757', '#ff6b7a', '#ffa502', '#2ed573', '#2ed573'];
    const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    
    return {
        score: Math.min(score, 4),
        color: colors[Math.min(score, 4)],
        text: texts[Math.min(score, 4)]
    };
}

function validateInput(input) {
    const value = input.value.trim();
    let isValid = true;
    let message = '';
    
    if (input.hasAttribute('required') && !value) {
        isValid = false;
        message = 'This field is required';
    } else if (input.type === 'email' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        isValid = false;
        message = 'Please enter a valid email address';
    } else if (input.type === 'password' && value && value.length < 8) {
        isValid = false;
        message = 'Password must be at least 8 characters';
    }
    
    input.classList.toggle('invalid', !isValid);
    input.classList.toggle('valid', isValid && value);
    
    // Remove existing error message
    const existingError = input.parentElement.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add error message if invalid
    if (!isValid && message) {
        const errorElement = document.createElement('div');
        errorElement.className = 'error-message';
        errorElement.style.cssText = `
            color: #ff4757;
            font-size: 0.8rem;
            margin-top: 4px;
            animation: fadeInUp 0.3s ease;
        `;
        errorElement.textContent = message;
        input.parentElement.appendChild(errorElement);
    }
    
    return isValid;
}

function handleFormSubmission(form) {
    const formData = new FormData(form);
    const submitBtn = form.querySelector('button[type="submit"]');
    
    if (submitBtn) {
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';
        
        // Simulate processing
        setTimeout(() => {
            if (form.id === 'loginForm' || form.classList.contains('auth-form')) {
                handleAuthentication(form, formData);
            } else {
                showNotification('Form submitted successfully!', 'success');
            }
            
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }, 2000);
    }
}

function handleAuthentication(form, formData) {
    const email = formData.get('email');
    const isLogin = form.id === 'loginForm' || window.location.pathname.includes('login');
    
    if (isLogin) {
        // Handle login
        localStorage.setItem('userLoggedIn', 'true');
        localStorage.setItem('userEmail', email);
        showNotification('Login successful! Redirecting...', 'success');
        
        setTimeout(() => {
            window.location.href = 'profile.html';
        }, 1500);
    } else {
        // Handle signup
        localStorage.setItem('userLoggedIn', 'true');
        localStorage.setItem('userEmail', email);
        showNotification('Account created successfully! Redirecting...', 'success');
        
        setTimeout(() => {
            window.location.href = 'profile.html';
        }, 1500);
    }
    
    trackEvent(isLogin ? 'user_login' : 'user_signup', { email });
}

function checkAuthStatus() {
    const isLoggedIn = localStorage.getItem('userLoggedIn') === 'true';
    const userEmail = localStorage.getItem('userEmail');
    
    // Update navigation based on auth status
    const loginBtn = document.querySelector('.login-btn');
    const signupBtn = document.querySelector('.p-btn');
    
    if (isLoggedIn && userEmail && loginBtn && signupBtn) {
        const userName = userEmail.split('@')[0];
        loginBtn.textContent = userName;
        loginBtn.href = 'profile.html';
        loginBtn.classList.remove('login-btn');
        loginBtn.classList.add('profile-link');
        
        signupBtn.textContent = 'Sign Out';
        signupBtn.href = '#';
        signupBtn.addEventListener('click', (e) => {
            e.preventDefault();
            logout();
        });
    }
}

function logout() {
    localStorage.removeItem('userLoggedIn');
    localStorage.removeItem('userEmail');
    showNotification('You have been logged out', 'info');
    setTimeout(() => {
        window.location.href = 'index.html';
    }, 1000);
}

// Enhanced Notification System
function showNotification(message, type = 'info') {
    // Create notification styles if not exists
    if (!document.querySelector('#notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 16px;
                max-width: 400px;
                z-index: 10000;
                animation: slideInRight 0.3s ease;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                backdrop-filter: blur(20px);
            }
            .notification-success { border-left: 4px solid var(--success-color); }
            .notification-error { border-left: 4px solid #ff4757; }
            .notification-info { border-left: 4px solid var(--accent-color); }
            .notification-content {
                display: flex;
                align-items: center;
                gap: 12px;
                color: var(--text-primary);
            }
            .notification-icon {
                font-weight: bold;
                font-size: 1.1rem;
            }
            .notification-success .notification-icon { color: var(--success-color); }
            .notification-error .notification-icon { color: #ff4757; }
            .notification-info .notification-icon { color: var(--accent-color); }
            .notification-message { flex: 1; }
            .notification-close {
                background: none;
                border: none;
                color: var(--text-muted);
                cursor: pointer;
                font-size: 1.2rem;
                padding: 0;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: color 0.3s ease;
            }
            .notification-close:hover { color: var(--text-primary); }
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOutRight {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(styles);
    }
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">
                ${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}
            </span>
            <span class="notification-message">${message}</span>
            <button class="notification-close">&times;</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        removeNotification(notification);
    });
    
    setTimeout(() => {
        removeNotification(notification);
    }, 5000);
}

function removeNotification(notification) {
    if (notification.parentNode) {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }
}

// Event Tracking
function trackEvent(eventName, data = {}) {
    console.log('Event tracked:', eventName, data);
    // In a real app, send to analytics service
}

// Interactive Features
document.addEventListener('click', (e) => {
    // Handle save job functionality
    if (e.target.classList.contains('save-btn')) {
        e.preventDefault();
        e.target.classList.toggle('saved');
        const isSaved = e.target.classList.contains('saved');
        showNotification(
            isSaved ? 'Job saved to your list!' : 'Job removed from saved list', 
            'success'
        );
        trackEvent('job_saved', { saved: isSaved });
    }
    
    // Handle apply button clicks
    if (e.target.classList.contains('apply-btn')) {
        e.preventDefault();
        showNotification('Application submitted successfully!', 'success');
        trackEvent('job_application_started');
    }
    
    // Handle profile prompt actions
    if (e.target.closest('.profile-actions')) {
        const action = e.target.textContent.includes('Create') ? 'signup' : 'signin';
        console.log(`User clicked ${action} from profile prompt`);
        trackEvent('profile_prompt_click', { action });
    }
    
    // Handle resource links
    if (e.target.closest('.resource-card') && e.target.tagName === 'A') {
        const resource = e.target.textContent;
        console.log(`User clicked on ${resource}`);
        trackEvent('resource_click', { resource });
    }
});

// Newsletter subscription
const newsletterForm = document.querySelector('.newsletter-form');
if (newsletterForm) {
    newsletterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const email = newsletterForm.querySelector('.email-input').value;
        if (email) {
            showNotification('Successfully subscribed to job alerts!', 'success');
            newsletterForm.querySelector('.email-input').value = '';
            trackEvent('newsletter_subscription', { email });
        }
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + K for search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('.search-input');
        if (searchInput) {
            searchInput.focus();
            showNotification('Search shortcut activated! Start typing...', 'info');
        }
    }
});

// Performance optimization
if ('requestIdleCallback' in window) {
    requestIdleCallback(() => {
        // Preload critical images
        const criticalImages = [
            // Add any critical image URLs here
        ];
        
        criticalImages.forEach(src => {
            const img = new Image();
            img.src = src;
        });
    });
}

// Service Worker registration for PWA capabilities
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // Can be implemented later for offline functionality
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const searchBtn = document.querySelector('.search-btn');
    const jobInput = document.querySelector('.search-input');
    const locationInput = document.querySelector('.location-input');
    const jobCards = document.querySelectorAll('.job-card');

    searchBtn.addEventListener('click', function (e) {
        e.preventDefault();
        const jobValue = jobInput.value.trim().toLowerCase();
        const locationValue = locationInput.value.trim().toLowerCase();

        jobCards.forEach(card => {
            const title = card.querySelector('.job-info h3').textContent.toLowerCase();
            const company = card.querySelector('.company').textContent.toLowerCase();
            const location = card.querySelector('.location').textContent.toLowerCase();

            // Check if job or company matches, and location matches (if provided)
            const matchesJob = jobValue === "" || title.includes(jobValue) || company.includes(jobValue);
            const matchesLocation = locationValue === "" || location.includes(locationValue);

            if (matchesJob && matchesLocation) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    });
});
