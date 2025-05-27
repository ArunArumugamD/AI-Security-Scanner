import logging
from functools import wraps
import time
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.scanner.analyzer import SecurityAnalyzer
import config

# ========== Rate Limiter Class ==========
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    def limit(self, max_requests=10, window_minutes=1):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                client_ip = request.remote_addr
                now = datetime.now()
                window_start = now - timedelta(minutes=window_minutes)

                self.requests[client_ip] = [
                    req_time for req_time in self.requests[client_ip]
                    if req_time > window_start
                ]

                if len(self.requests[client_ip]) >= max_requests:
                    return jsonify({
                        'success': False,
                        'error': f'Rate limit exceeded. Max {max_requests} requests per {window_minutes} minute(s).'
                    }), 429

                self.requests[client_ip].append(now)
                return f(*args, **kwargs)
            return wrapped
        return decorator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Initialize rate limiter and analyzer
rate_limiter = RateLimiter()
analyzer = SecurityAnalyzer()

# Flask app setup
app = Flask(__name__,
            template_folder='../../templates',
            static_folder='../../static')
CORS(app)

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
@rate_limiter.limit(max_requests=10, window_minutes=1)
def scan_code():
    """API endpoint for code scanning with enhanced error handling"""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        if 'code' not in data:
            return jsonify({'success': False, 'error': 'Missing required field: code'}), 400

        code = data.get('code', '')
        filename = data.get('filename', 'uploaded_code.py')
        language = data.get('language')

        if len(code.encode('utf-8')) > config.MAX_FILE_SIZE:
            return jsonify({'success': False, 'error': 'Code size exceeds maximum allowed'}), 400

        logging.info(f"Scan request from {request.remote_addr} - {len(code)} bytes")

        start_time = time.time()
        MAX_ANALYSIS_TIME = 30

        results = analyzer.analyze_code(code, filename, language)

        analysis_time = time.time() - start_time
        if analysis_time > MAX_ANALYSIS_TIME:
            logging.warning(f"Analysis took too long: {analysis_time:.2f}s")

        results['analysis_time'] = round(analysis_time, 2)
        return jsonify(results)

    except MemoryError:
        return jsonify({'success': False, 'error': 'Code is too large or complex to analyze'}), 413

    except TimeoutError:
        return jsonify({'success': False, 'error': 'Analysis timed out'}), 408

    except Exception as e:
        logging.error(f"Error in scan_code endpoint: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during analysis. Please try again.'}), 500

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get list of security rules"""
    return jsonify({
        'rules': analyzer.rules,
        'count': len(analyzer.rules)
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'error': 'Request too large. Maximum size is 1MB.'}), 413

if __name__ == '__main__':
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
