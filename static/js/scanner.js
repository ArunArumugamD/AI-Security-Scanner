// Global variable to store last scan results
let lastScanResults = null;

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
const fileInput = document.getElementById('fileInput');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const exportReportBtn = document.getElementById('exportReportBtn');
const exportActions = document.querySelector('.export-actions');

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
fileInput.addEventListener('change', handleFileUpload);
exportJsonBtn.addEventListener('click', () => exportResults('json'));
exportReportBtn.addEventListener('click', () => exportResults('report'));

// File upload handler
async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.py')) {
        showToast('Please upload a Python file (.py)', 'error');
        return;
    }
    
    if (file.size > 1024 * 1024) { // 1MB limit
        showToast('File size exceeds 1MB limit', 'error');
        return;
    }
    
    try {
        const text = await file.text();
        codeInput.value = text;
        showToast('File loaded successfully', 'success');
    } catch (error) {
        showToast('Error reading file', 'error');
        console.error('File read error:', error);
    }
    
    // Reset the input
    event.target.value = '';
}

// Toast notification system
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

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
            // Store results for export
            lastScanResults = {
                ...data,
                code: code,
                timestamp: new Date().toISOString()
            };
            
            displayResults(data);
            
            // Show export buttons
            exportActions.style.display = 'flex';
            
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

// Enhanced vulnerability element with copy button
function createVulnerabilityElement(vuln) {
    const div = document.createElement('div');
    div.className = `vulnerability-item ${vuln.severity.toLowerCase()}`;
    
    const snippetId = `snippet-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
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
        <div class="code-snippet-container">
            <div class="snippet-header">
                <span>Code snippet</span>
                <button class="copy-btn" onclick="copyCodeSnippet('${snippetId}')" title="Copy code">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
            <pre class="code-snippet" id="${snippetId}"><code class="language-python">${escapeHtml(vuln.code_snippet)}</code></pre>
        </div>
    `;
    
    // Apply syntax highlighting after adding to DOM
    setTimeout(() => {
        const codeElement = document.querySelector(`#${snippetId} code`);
        if (codeElement && typeof Prism !== 'undefined') {
            Prism.highlightElement(codeElement);
        }
    }, 0);
    
    return div;
}

// Copy code snippet function
function copyCodeSnippet(snippetId) {
    const snippet = document.getElementById(snippetId);
    if (!snippet) return;
    
    const text = snippet.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Code copied to clipboard', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Failed to copy code', 'error');
    });
}

// Export functionality
function exportResults(format) {
    if (!lastScanResults) {
        showToast('No results to export', 'error');
        return;
    }
    
    if (format === 'json') {
        exportAsJSON();
    } else if (format === 'report') {
        exportAsReport();
    }
}

function exportAsJSON() {
    const dataStr = JSON.stringify(lastScanResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-scan-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showToast('Results exported as JSON', 'success');
}

function exportAsReport() {
    if (!lastScanResults) return;
    
    let report = `SECURITY SCAN REPORT
Generated: ${new Date().toLocaleString()}
=====================================

SUMMARY
-------
Total Issues: ${lastScanResults.summary.total}
Risk Score: ${lastScanResults.summary.risk_score}/100
Lines of Code: ${lastScanResults.metrics.lines_of_code}
Analysis Time: ${lastScanResults.analysis_time}s

VULNERABILITY BREAKDOWN
----------------------
`;

    // Add severity breakdown
    if (lastScanResults.summary.by_severity) {
        Object.entries(lastScanResults.summary.by_severity).forEach(([severity, count]) => {
            report += `${severity}: ${count}\n`;
        });
    }

    report += '\nDETAILED FINDINGS\n-----------------\n';

    // Group by severity
    const grouped = groupVulnerabilitiesBySeverity(lastScanResults.vulnerabilities);
    
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(severity => {
        if (grouped[severity] && grouped[severity].length > 0) {
            report += `\n${severity} SEVERITY (${grouped[severity].length})\n`;
            report += '='.repeat(severity.length + 15) + '\n\n';
            
            grouped[severity].forEach((vuln, index) => {
                report += `${index + 1}. ${vuln.name}\n`;
                report += `   Location: Line ${vuln.line}, Column ${vuln.column}\n`;
                report += `   Message: ${vuln.message}\n`;
                if (vuln.cwe) report += `   CWE: ${vuln.cwe}\n`;
                if (vuln.owasp) report += `   OWASP: ${vuln.owasp}\n`;
                report += `   Code:\n${vuln.code_snippet.split('\n').map(line => '      ' + line).join('\n')}\n\n`;
            });
        }
    });

    report += '\n=====================================\nEnd of Report';

    // Download report
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-report-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showToast('Report exported as text file', 'success');
}

function clearCode() {
    codeInput.value = '';
    results.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-clipboard-list"></i>
            <p>No scan results yet. Paste some code and click "Scan Code" to begin.</p>
        </div>
    `;
    exportActions.style.display = 'none';
    lastScanResults = null;
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

// Make copyCodeSnippet available globally
window.copyCodeSnippet = copyCodeSnippet;

// Add all styles
const style = document.createElement('style');
style.textContent = `
/* Existing styles */
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

/* New styles for enhanced features */
.header-actions {
    display: flex;
    gap: 10px;
}

.export-actions {
    display: flex;
    gap: 10px;
}

.code-snippet-container {
    margin-top: 10px;
}

.snippet-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: #1e293b;
    padding: 5px 10px;
    border-radius: 5px 5px 0 0;
    font-size: 0.85rem;
    color: #94a3b8;
}

[data-theme="dark"] .snippet-header {
    background-color: #0f172a;
}

.copy-btn {
    background: none;
    border: none;
    color: #94a3b8;
    cursor: pointer;
    padding: 5px;
    border-radius: 3px;
    transition: all 0.2s;
}

.copy-btn:hover {
    background-color: rgba(255, 255, 255, 0.1);
    color: #e2e8f0;
}

.code-snippet {
    margin: 0;
    border-radius: 0 0 5px 5px;
    font-size: 0.9rem;
}

/* Toast notifications */
.toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 15px 20px;
    border-radius: 5px;
    color: white;
    font-weight: 500;
    transform: translateX(400px);
    transition: transform 0.3s ease;
    z-index: 1001;
}

.toast.show {
    transform: translateX(0);
}

.toast.success {
    background-color: #10b981;
}

.toast.error {
    background-color: #ef4444;
}

.toast.info {
    background-color: #3b82f6;
}

/* File input label styling */
label[for="fileInput"] {
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}

/* Prism.js overrides for dark theme */
[data-theme="dark"] pre[class*="language-"] {
    background: #0f172a;
}

[data-theme="dark"] code[class*="language-"] {
    color: #e2e8f0;
}
`;
document.head.appendChild(style);