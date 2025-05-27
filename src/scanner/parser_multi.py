import ast
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class CodeNode:
    type: str
    value: str
    line: int
    column: int
    children: List['CodeNode'] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []

class MultiLanguageParser:
    """Parser that supports multiple programming languages"""
    
    def __init__(self):
        self.parsers = {
            'python': PythonParser(),
            'javascript': JavaScriptParser(),
            'java': JavaParser(),
            'php': PHPParser()
        }
    
    def parse(self, code: str, language: str) -> Dict[str, Any]:
        """Parse code based on language"""
        if language not in self.parsers:
            return {
                'error': f'Language {language} not supported',
                'ast': None
            }
        
        return self.parsers[language].parse(code)
    
    def detect_language(self, code: str, filename: str = None) -> str:
        """Auto-detect language from filename or code content"""
        # Check filename extension first
        if filename:
            ext_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.jsx': 'javascript',
                '.java': 'java',
                '.php': 'php'
            }
            for ext, lang in ext_map.items():
                if filename.endswith(ext):
                    return lang
        
        # Simple heuristics for language detection
        if 'def ' in code and ':' in code:
            return 'python'
        elif 'function' in code or 'const ' in code or 'let ' in code:
            return 'javascript'
        elif 'public class' in code or 'public static void' in code:
            return 'java'
        elif '<?php' in code or '$' in code and ';' in code:
            return 'php'
        
        return 'python'  # Default

class PythonParser:
    """Python code parser"""
    
    def parse(self, code: str) -> Dict[str, Any]:
        """Parse Python code and return AST with metadata"""
        try:
            tree = ast.parse(code)
            
            return {
                'ast': tree,
                'lines': code.splitlines(),
                'language': 'python',
                'imports': self._extract_imports(tree),
                'functions': self._extract_functions(tree),
                'strings': self._extract_strings(tree),
                'calls': self._extract_function_calls(tree)
            }
        except SyntaxError as e:
            return {
                'error': f'Python syntax error at line {e.lineno}: {e.msg}',
                'ast': None,
                'language': 'python'
            }
    
    def _extract_imports(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract all imports from the code"""
        imports = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({
                        'module': alias.name,
                        'alias': alias.asname,
                        'line': node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    imports.append({
                        'module': f"{module}.{alias.name}",
                        'alias': alias.asname,
                        'line': node.lineno
                    })
        
        return imports
    
    def _extract_functions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract all function definitions"""
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'line': node.lineno,
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [d.id for d in node.decorator_list if hasattr(d, 'id')]
                })
        
        return functions
    
    def _extract_strings(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract all string literals"""
        strings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.append({
                    'value': node.value,
                    'line': node.lineno,
                    'column': node.col_offset
                })
        
        return strings
    
    def _extract_function_calls(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract all function calls"""
        calls = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name:
                    calls.append({
                        'function': func_name,
                        'line': node.lineno,
                        'args_count': len(node.args)
                    })
        
        return calls
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

class JavaScriptParser:
    """JavaScript code parser using regex patterns"""
    
    def parse(self, code: str) -> Dict[str, Any]:
        """Parse JavaScript code using pattern matching"""
        return {
            'ast': None,  # Simplified - no AST for JS
            'lines': code.splitlines(),
            'language': 'javascript',
            'functions': self._extract_functions(code),
            'strings': self._extract_strings(code),
            'calls': self._extract_function_calls(code)
        }
    
    def _extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        functions = []
        
        # Match function declarations and expressions
        patterns = [
            r'function\s+(\w+)\s*\(',
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>',
            r'let\s+(\w+)\s*=\s*\([^)]*\)\s*=>',
            r'var\s+(\w+)\s*=\s*function\s*\('
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                functions.append({
                    'name': match.group(1),
                    'line': line_num
                })
        
        return functions
    
    def _extract_strings(self, code: str) -> List[Dict[str, Any]]:
        """Extract string literals"""
        strings = []
        
        # Match strings with quotes
        string_pattern = r'["\']([^"\']*)["\']'
        
        for match in re.finditer(string_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            strings.append({
                'value': match.group(1),
                'line': line_num
            })
        
        return strings
    
    def _extract_function_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract function calls"""
        calls = []
        
        # Match function calls
        call_pattern = r'(\w+)\s*\('
        
        # Common keywords to exclude
        keywords = {'if', 'while', 'for', 'switch', 'catch', 'function'}
        
        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            if func_name not in keywords:
                line_num = code[:match.start()].count('\n') + 1
                calls.append({
                    'function': func_name,
                    'line': line_num
                })
        
        return calls

class JavaParser:
    """Java code parser using regex patterns"""
    
    def parse(self, code: str) -> Dict[str, Any]:
        """Parse Java code using pattern matching"""
        return {
            'ast': None,  # Simplified - no AST for Java
            'lines': code.splitlines(),
            'language': 'java',
            'functions': self._extract_methods(code),
            'strings': self._extract_strings(code),
            'calls': self._extract_method_calls(code)
        }
    
    def _extract_methods(self, code: str) -> List[Dict[str, Any]]:
        """Extract method definitions"""
        methods = []
        
        # Match method declarations
        method_pattern = r'(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\('
        
        for match in re.finditer(method_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            methods.append({
                'name': match.group(3),
                'line': line_num
            })
        
        return methods
    
    def _extract_strings(self, code: str) -> List[Dict[str, Any]]:
        """Extract string literals"""
        strings = []
        
        # Match strings with double quotes
        string_pattern = r'"([^"]*)"'
        
        for match in re.finditer(string_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            strings.append({
                'value': match.group(1),
                'line': line_num
            })
        
        return strings
    
    def _extract_method_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract method calls"""
        calls = []
        
        # Match method calls
        call_pattern = r'(\w+)\s*\('
        
        # Common keywords to exclude
        keywords = {'if', 'while', 'for', 'switch', 'catch', 'new', 'return'}
        
        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            if func_name not in keywords:
                line_num = code[:match.start()].count('\n') + 1
                calls.append({
                    'function': func_name,
                    'line': line_num
                })
        
        return calls

class PHPParser:
    """PHP code parser using regex patterns"""
    
    def parse(self, code: str) -> Dict[str, Any]:
        """Parse PHP code using pattern matching"""
        return {
            'ast': None,  # Simplified - no AST for PHP
            'lines': code.splitlines(),
            'language': 'php',
            'functions': self._extract_functions(code),
            'strings': self._extract_strings(code),
            'calls': self._extract_function_calls(code)
        }
    
    def _extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        functions = []
        
        # Match function declarations
        function_pattern = r'function\s+(\w+)\s*\('
        
        for match in re.finditer(function_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            functions.append({
                'name': match.group(1),
                'line': line_num
            })
        
        return functions
    
    def _extract_strings(self, code: str) -> List[Dict[str, Any]]:
        """Extract string literals"""
        strings = []
        
        # Match strings with quotes
        string_patterns = [r'"([^"]*)"', r"'([^']*)'"]
        
        for pattern in string_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                strings.append({
                    'value': match.group(1),
                    'line': line_num
                })
        
        return strings
    
    def _extract_function_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract function calls"""
        calls = []
        
        # Match function calls
        call_pattern = r'(\w+)\s*\('
        
        # Common keywords to exclude
        keywords = {'if', 'while', 'for', 'foreach', 'switch', 'function', 'array'}
        
        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            if func_name not in keywords:
                line_num = code[:match.start()].count('\n') + 1
                calls.append({
                    'function': func_name,
                    'line': line_num
                })
        
        return calls