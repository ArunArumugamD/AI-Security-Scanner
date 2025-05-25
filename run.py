#!/usr/bin/env python
"""
AI Security Scanner - Main Entry Point
"""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.web.app import app
import config

if __name__ == '__main__':
    print(f"""
╔═══════════════════════════════════════╗
║      AI Security Scanner v1.0         ║
║   Detecting vulnerabilities with AI   ║
╚═══════════════════════════════════════╝

Starting server at http://{config.HOST}:{config.PORT}
Press Ctrl+C to stop
    """)
    
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )