import os
from pathlib import Path
import tempfile

# Base directory
BASE_DIR = Path(__file__).parent

# Data directories
DATA_DIR = BASE_DIR / 'data'
RULES_DIR = DATA_DIR / 'rules'
MODELS_DIR = DATA_DIR / 'models'

# Web configuration
# Use environment variables for Render deployment
HOST = os.environ.get('HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', 5000))
DEBUG = os.environ.get('FLASK_ENV') != 'production'

# Flask configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# File upload configuration for Render
# Use /tmp directory on Render (ephemeral filesystem)
if os.environ.get('PORT'):  # Running on Render
    UPLOAD_FOLDER = '/tmp/uploads'
else:  # Running locally
    UPLOAD_FOLDER = BASE_DIR / 'uploads'

# Create upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Scanner configuration
MAX_FILE_SIZE = int(os.environ.get('MAX_CONTENT_LENGTH', 1024 * 1024))  # 1MB default
SUPPORTED_LANGUAGES = ['python', 'javascript', 'java', 'php']

# Vulnerability types
VULNERABILITY_TYPES = [
    'SQL_INJECTION',
    'XSS',
    'HARDCODED_SECRET',
    'PATH_TRAVERSAL',
    'COMMAND_INJECTION',
    'INSECURE_RANDOM',
    'WEAK_CRYPTO',
    'XXE',
    'INSECURE_DESERIALIZATION',
    'OPEN_REDIRECT'
]

# Severity levels
SEVERITY_LEVELS = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
}