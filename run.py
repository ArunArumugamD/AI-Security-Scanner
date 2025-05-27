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
    # Get configuration from environment or config file
    port = int(os.environ.get('PORT', config.PORT))
    host = '0.0.0.0' if os.environ.get('PORT') else config.HOST
    debug = False if os.environ.get('PORT') else config.DEBUG
    
    # Only show banner in development
    if not os.environ.get('PORT'):
        print(f"""
╔═══════════════════════════════════════╗
║      AI Security Scanner v1.0         ║
║   Detecting vulnerabilities with AI   ║
╚═══════════════════════════════════════╝

Starting server at http://{host}:{port}
Press Ctrl+C to stop
        """)
    
    app.run(
        host=host,
        port=port,
        debug=debug
    )