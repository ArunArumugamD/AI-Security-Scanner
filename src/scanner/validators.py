import re
from typing import Tuple, Optional

class CodeValidator:
    """Validate code input for security scanning"""
    
    # Limits
    MAX_FILE_SIZE = 1024 * 1024  # 1MB
    MAX_LINES = 10000
    MIN_CODE_LENGTH = 10
    
    @staticmethod
    def validate_code_input(code: str, filename: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate code input before scanning
        Returns: (is_valid, error_message)
        """
        
        # Check if code is empty
        if not code or not code.strip():
            return False, "Please provide some code to scan"
        
        # Check minimum length
        if len(code.strip()) < CodeValidator.MIN_CODE_LENGTH:
            return False, "Code is too short. Please provide at least 10 characters"
        
        # Check code size
        code_size = len(code.encode('utf-8'))
        if code_size > CodeValidator.MAX_FILE_SIZE:
            size_mb = code_size / (1024 * 1024)
            return False, f"Code size ({size_mb:.2f}MB) exceeds maximum allowed size (1MB)"
        
        # Check number of lines
        lines = code.splitlines()
        if len(lines) > CodeValidator.MAX_LINES:
            return False, f"Code has too many lines ({len(lines)}). Maximum allowed is {CodeValidator.MAX_LINES}"
        
        # Check for binary content
        if '\x00' in code or '\x1f' in code:
            return False, "Binary content detected. Please provide text-based source code only"
        
        # Check if it looks like Python code (basic heuristic)
        if filename and filename.endswith('.py'):
            if not CodeValidator._looks_like_python(code):
                return False, "The code doesn't appear to be valid Python. Please check your syntax"
        
        # Check for potential malicious patterns in the code itself
        if CodeValidator._contains_malicious_patterns(code):
            return False, "Code contains potentially malicious patterns"
        
        return True, ""
    
    @staticmethod
    def _looks_like_python(code: str) -> bool:
        """Basic heuristic to check if code looks like Python"""
        # Very basic check - just see if it has any Python-like elements
        python_indicators = [
            'import ', 'from ', 'def ', 'class ', 'if ', 'for ', 'while ',
            'return ', 'print(', ':', '==', '!=', 'True', 'False', 'None'
        ]
        
        code_lower = code.lower()
        return any(indicator in code_lower for indicator in python_indicators)
    
    @staticmethod
    def _contains_malicious_patterns(code: str) -> bool:
        """Check for patterns that might indicate malicious intent"""
        # Patterns that might indicate someone trying to break the scanner
        malicious_patterns = [
            r'exec\s*\(\s*["\'].*rm\s+-rf.*["\']',  # Attempting to delete files
            r'__import__.*os.*system',  # Dynamic import with system calls
            r'eval\s*\(\s*compile\s*\(',  # Eval with compile
            r'pickle\.loads.*urlopen',  # Pickle from URL (very dangerous)
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for security"""
        if not filename:
            return "untitled.py"
        
        # Remove path traversal attempts
        filename = filename.replace('..', '').replace('/', '').replace('\\', '')
        
        # Keep only alphanumeric, dash, underscore, and dot
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, 'py')
            filename = name[:240] + '.' + ext
        
        # Ensure it has an extension
        if not filename.endswith('.py'):
            filename += '.py'
        
        return filename
    
    @staticmethod
    def validate_language(language: str) -> Tuple[bool, str]:
        """Validate programming language selection"""
        valid_languages = ['python', 'javascript', 'java', 'php', 'auto']
        
        if language and language.lower() not in valid_languages:
            return False, f"Unsupported language: {language}. Supported: {', '.join(valid_languages)}"
        
        return True, ""