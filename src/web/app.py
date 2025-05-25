from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.scanner.analyzer import SecurityAnalyzer
import config

app = Flask(__name__, 
           template_folder='../../templates',
           static_folder='../../static')
CORS(app)

# Initialize analyzer
analyzer = SecurityAnalyzer()

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_code():
    """API endpoint for code scanning"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({
                'success': False,
                'error': 'No code provided'
            }), 400
        
        code = data['code']
        filename = data.get('filename', 'uploaded_code.py')
        
        # Check file size
        if len(code.encode('utf-8')) > config.MAX_FILE_SIZE:
            return jsonify({
                'success': False,
                'error': 'Code size exceeds maximum allowed'
            }), 400
        
        # Analyze code
        results = analyzer.analyze_code(code, filename)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get list of security rules"""
    return jsonify({
        'rules': analyzer.rules,
        'count': len(analyzer.rules)
    })

if __name__ == '__main__':
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)