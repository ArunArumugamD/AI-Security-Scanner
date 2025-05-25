// Theme management
const themeToggle = document.getElementById('themeToggle');
const htmlElement = document.documentElement;

if (!localStorage.getItem('theme')) {
    localStorage.setItem('theme', 'dark');
    htmlElement.setAttribute('data-theme', 'dark');
    updateThemeIcon('dark');
}

// Check for saved theme preference or default to dark mode
const currentTheme = localStorage.getItem('theme') || 'dark';
htmlElement.setAttribute('data-theme', currentTheme);
updateThemeIcon(currentTheme);

// Theme toggle functionality
themeToggle.addEventListener('click', () => {
    const currentTheme = htmlElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    htmlElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
});

function updateThemeIcon(theme) {
    const icon = themeToggle.querySelector('i');
    if (theme === 'dark') {
        icon.className = 'fas fa-sun';
        themeToggle.title = 'Switch to light mode';
    } else {
        icon.className = 'fas fa-moon';
        themeToggle.title = 'Switch to dark mode';
    }
}

// Scanner functionality
const codeInput = document.getElementById('codeInput');
const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const exampleBtn = document.getElementById('exampleBtn');
const results = document.getElementById('results');
const loadingOverlay = document.getElementById('loadingOverlay');

// Example vulnerable code
const exampleCode = `import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials - Security Issue!
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query)
    return str(result.fetchone())

@app.route('/search')
def search():
    # Another SQL injection
    term = request.args.get('q')
    conn = sqlite3.connect('products.db')
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    results = conn.execute(query)
    return str(results.fetchall())

@app.route('/run')
def run_command():
    # Command injection vulnerability
    cmd = request.args.get('cmd')
    output = os.system(cmd)
    return str(output)

@app.route('/eval')
def evaluate():
    # Code injection via eval
    expression = request.args.get('expr')
    result = eval(expression)
    return str(result)

def generate_token():
    # Weak random number generation
    import random
    token = random.randint(1000, 9999)
    return str(token)

if __name__ == '__main__':
    app.run(debug=True)
`;

// Event listeners
scanBtn.addEventListener('click', scanCode);
clearBtn.addEventListener('click', clearCode);
exampleBtn.addEventListener('click', loadExample);

// Functions
async function scanCode() {
    const code = codeInput.value.trim();
    
    if (!code) {
        showError('Please enter some code to scan');
        return;
    }
    
    // Show loading
    loadingOverlay.classList.add('active');
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                filename: 'user_code.py'
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data);
        } else {
            showError(data.error || 'An error occurred during scanning');
        }
    } catch (error) {
        showError('Failed to connect to the scanner service');
        console.error(error);
    } finally {
        loadingOverlay.classList.remove('active');
    }
}

function displayResults(data) {
    results.innerHTML = '';
    
    if (data.vulnerabilities.length === 0) {
        results.innerHTML = `
            <div class="success-message">
                <i class="fas fa-check-circle"></i>
                <h3>No vulnerabilities found!</h3>
                <p>Your code appears to be secure based on our analysis.</p>
            </div>
        `;
        return;
    }
    
    // Summary section
    const summaryHtml = `
        <div class="summary-section">
            <h3>Scan Summary</h3>
            <div class="summary-stats">
                <div class="stat-item">
                    <div class="stat-value">${data.summary.total}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${data.summary.risk_score}</div>
                    <div class="stat-label">Risk Score</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${data.metrics.lines_of_code}</div>
                    <div class="stat-label">Lines of Code</div>
                </div>
            </div>
        </div>
    `;
    
    results.innerHTML = summaryHtml;
    
    // Vulnerabilities
    const vulnContainer = document.createElement('div');
    vulnContainer.className = 'vulnerabilities-container';
    
    data.vulnerabilities.forEach(vuln => {
        const vulnElement = createVulnerabilityElement(vuln);
        vulnContainer.appendChild(vulnElement);
    });
    
    results.appendChild(vulnContainer);
}

function createVulnerabilityElement(vuln) {
    const div = document.createElement('div');
    div.className = `vulnerability-item ${vuln.severity.toLowerCase()}`;
    
    div.innerHTML = `
        <div class="vuln-header">
            <span class="vuln-title">${vuln.name}</span>
            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
        </div>
        <div class="vuln-details">
            <div class="vuln-location">
                <i class="fas fa-map-marker-alt"></i> Line ${vuln.line}, Column ${vuln.column}
            </div>
            <div class="vuln-message">${vuln.message}</div>
            ${vuln.cwe ? `<div class="vuln-cwe"><strong>CWE:</strong> ${vuln.cwe}</div>` : ''}
            ${vuln.owasp ? `<div class="vuln-owasp"><strong>OWASP:</strong> ${vuln.owasp}</div>` : ''}
        </div>
        <div class="code-snippet">${escapeHtml(vuln.code_snippet)}</div>
    `;
    
    return div;
}

function clearCode() {
    codeInput.value = '';
    results.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-clipboard-list"></i>
            <p>No scan results yet. Paste some code and click "Scan Code" to begin.</p>
        </div>
    `;
}

function loadExample() {
    codeInput.value = exampleCode;
}

function showError(message) {
    results.innerHTML = `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <h3>Error</h3>
            <p>${message}</p>
        </div>
    `;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Add success and error message styles
const style = document.createElement('style');
style.textContent = `
.success-message, .error-message {
    text-align: center;
    padding: 40px;
    border-radius: 8px;
}

.success-message {
    background-color: #d1fae5;
    color: #065f46;
}

.success-message i {
    font-size: 3rem;
    margin-bottom: 20px;
    color: #10b981;
}

.error-message {
    background-color: #fee2e2;
    color: #991b1b;
}

.error-message i {
    font-size: 3rem;
    margin-bottom: 20px;
    color: #ef4444;
}

.vulnerabilities-container {
    margin-top: 20px;
}
`;
document.head.appendChild(style);