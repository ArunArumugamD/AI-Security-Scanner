// Theme management
const themeToggle = document.getElementById('themeToggle');
const htmlElement = document.documentElement;

// Force dark mode on first load if no preference is set
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

// Add client-side validation
function validateCode(code) {
    const MAX_SIZE = 1024 * 1024; // 1MB
    const MIN_LENGTH = 10;
    
    if (!code || code.trim().length === 0) {
        return { valid: false, error: 'Please enter some code to scan' };
    }
    
    if (code.trim().length < MIN_LENGTH) {
        return { valid: false, error: 'Code is too short. Please provide at least 10 characters' };
    }
    
    // Check size
    const sizeInBytes = new Blob([code]).size;
    if (sizeInBytes > MAX_SIZE) {
        const sizeMB = (sizeInBytes / (1024 * 1024)).toFixed(2);
        return { valid: false, error: `Code size (${sizeMB}MB) exceeds maximum allowed size (1MB)` };
    }
    
    return { valid: true };
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

// Enhanced scanCode function with better error handling
async function scanCode() {
    const code = codeInput.value;
    
    // Client-side validation
    const validation = validateCode(code);
    if (!validation.valid) {
        showError(validation.error);
        return;
    }
    
    // Show loading
    loadingOverlay.classList.add('active');
    
    // Disable scan button to prevent double-clicks
    scanBtn.disabled = true;
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                filename: 'user_code.py'
            }),
            // Add timeout
            signal: AbortSignal.timeout(30000) // 30 second timeout
        });
        
        const data = await response.json();
        
        if (response.status === 429) {
            showError('Rate limit exceeded. Please wait a moment before scanning again.');
            return;
        }
        
        if (response.status === 413) {
            showError('Code is too large. Please reduce the size and try again.');
            return;
        }
        
        if (response.status === 408) {
            showError('Analysis timed out. Please try with smaller code.');
            return;
        }
        
        if (!response.ok) {
            showError(data.error || `Server error: ${response.status}`);
            return;
        }
        
        if (data.success) {
            displayResults(data);
            
            // Show analysis time if available
            if (data.analysis_time) {
                console.log(`Analysis completed in ${data.analysis_time}s`);
            }
            
            // Show warning if partial analysis
            if (data.warning) {
                showWarning(data.warning);
            }
        } else {
            showError(data.error || 'An error occurred during scanning');
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            showError('Request timed out. Please try with smaller code.');
        } else if (error.message.includes('Failed to fetch')) {
            showError('Unable to connect to the scanner service. Please check your connection.');
        } else {
            showError('An unexpected error occurred. Please try again.');
        }
        console.error('Scan error:', error);
    } finally {
        loadingOverlay.classList.remove('active');
        scanBtn.disabled = false;
    }
}

// Add warning display function
function showWarning(message) {
    const warningDiv = document.createElement('div');
    warningDiv.className = 'warning-message';
    warningDiv.innerHTML = `
        <i class="fas fa-exclamation-circle"></i>
        <p>${message}</p>
    `;
    
    // Insert at the top of results
    results.insertBefore(warningDiv, results.firstChild);
}

// Enhanced displayResults function
function displayResults(data) {
    results.innerHTML = '';
    
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        results.innerHTML = `
            <div class="success-message">
                <i class="fas fa-check-circle"></i>
                <h3>No vulnerabilities found!</h3>
                <p>Your code appears to be secure based on our analysis.</p>
                ${data.analysis_time ? `<p class="analysis-time">Analysis completed in ${data.analysis_time}s</p>` : ''}
            </div>
        `;
        return;
    }
    
    // Summary section with enhanced stats
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
            ${data.analysis_time ? `<p class="analysis-time">Analysis completed in ${data.analysis_time}s</p>` : ''}
        </div>
    `;
    
    results.innerHTML = summaryHtml;
    
    // Group vulnerabilities by severity
    const vulnsBySeverity = groupVulnerabilitiesBySeverity(data.vulnerabilities);
    
    // Create vulnerabilities container
    const vulnContainer = document.createElement('div');
    vulnContainer.className = 'vulnerabilities-container';
    
    // Display vulnerabilities grouped by severity
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(severity => {
        if (vulnsBySeverity[severity] && vulnsBySeverity[severity].length > 0) {
            const severityGroup = document.createElement('div');
            severityGroup.className = 'severity-group';
            severityGroup.innerHTML = `<h4 class="severity-header ${severity.toLowerCase()}">${severity} (${vulnsBySeverity[severity].length})</h4>`;
            
            vulnsBySeverity[severity].forEach(vuln => {
                const vulnElement = createVulnerabilityElement(vuln);
                severityGroup.appendChild(vulnElement);
            });
            
            vulnContainer.appendChild(severityGroup);
        }
    });
    
    results.appendChild(vulnContainer);
}

// Helper function to group vulnerabilities by severity
function groupVulnerabilitiesBySeverity(vulnerabilities) {
    return vulnerabilities.reduce((groups, vuln) => {
        const severity = vuln.severity || 'LOW';
        if (!groups[severity]) {
            groups[severity] = [];
        }
        groups[severity].push(vuln);
        return groups;
    }, {});
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

// Add all styles
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

[data-theme="dark"] .success-message {
    background-color: #064e3b;
    color: #6ee7b7;
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

[data-theme="dark"] .error-message {
    background-color: #7f1d1d;
    color: #fca5a5;
}

.error-message i {
    font-size: 3rem;
    margin-bottom: 20px;
    color: #ef4444;
}

.vulnerabilities-container {
    margin-top: 20px;
}

.warning-message {
    background-color: #fef3c7;
    color: #92400e;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 10px;
}

[data-theme="dark"] .warning-message {
    background-color: #78350f;
    color: #fef3c7;
}

.warning-message i {
    font-size: 1.5rem;
    color: #f59e0b;
}

.analysis-time {
    font-size: 0.9rem;
    opacity: 0.8;
    margin-top: 10px;
    text-align: center;
}

.severity-group {
    margin-bottom: 30px;
}

.severity-header {
    font-size: 1.2rem;
    margin-bottom: 15px;
    padding: 10px;
    border-radius: 5px;
}

.severity-header.critical {
    background-color: rgba(239, 68, 68, 0.1);
    color: var(--danger-color);
}

.severity-header.high {
    background-color: rgba(220, 38, 38, 0.1);
    color: #dc2626;
}

.severity-header.medium {
    background-color: rgba(245, 158, 11, 0.1);
    color: var(--warning-color);
}

.severity-header.low {
    background-color: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
}

[data-theme="dark"] .severity-header {
    background-color: rgba(255, 255, 255, 0.05);
}

#scanBtn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}
`;
document.head.appendChild(style);