import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Data directories
DATA_DIR = BASE_DIR / 'data'
RULES_DIR = DATA_DIR / 'rules'
MODELS_DIR = DATA_DIR / 'models'

# Web configuration
HOST = '127.0.0.1'
PORT = 5000
DEBUG = True

# Scanner configuration
MAX_FILE_SIZE = 1024 * 1024  # 1MB
SUPPORTED_LANGUAGES = ['python']

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