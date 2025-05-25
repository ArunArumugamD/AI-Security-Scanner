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

class PythonParser:
    """Simple Python code parser for security analysis"""
    
    def __init__(self):
        self.vulnerabilities = []
        
    def parse(self, code: str) -> Dict[str, Any]:
        """Parse Python code and return AST with metadata"""
        try:
            tree = ast.parse(code)
            
            return {
                'ast': tree,
                'lines': code.splitlines(),
                'imports': self._extract_imports(tree),
                'functions': self._extract_functions(tree),
                'strings': self._extract_strings(tree),
                'calls': self._extract_function_calls(tree)
            }
        except SyntaxError as e:
            return {
                'error': f'Syntax error at line {e.lineno}: {e.msg}',
                'ast': None
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
            # Simple approach - just return the attribute name
            # This handles most common cases like conn.execute()
            return node.func.attr
        return None