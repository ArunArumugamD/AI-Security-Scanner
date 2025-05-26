import logging
import traceback
from src.scanner.validators import CodeValidator
import re
import json
import ast
from typing import List, Dict, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import config

@dataclass
class Vulnerability:
    rule_id: str
    name: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    code_snippet: str
    cwe: str = ""
    owasp: str = ""
    confidence: float = 1.0

class SecurityAnalyzer:
    """Main security analyzer combining rules and ML detection"""
    
    def __init__(self):
        self.rules = self._load_rules()
        self.parser = None
        
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load security rules from JSON file"""
        rules_file = config.RULES_DIR / 'security_rules.json'
        
        if not rules_file.exists():
            return []
            
        with open(rules_file, 'r') as f:
            data = json.load(f)
            return data.get('rules', [])
    
    def analyze_code(self, code: str, filename: str = "uploaded_code.py") -> Dict[str, Any]:
        """Analyze code for security vulnerabilities"""
        try:

            is_valid, error_msg = CodeValidator.validate_code_input(code,filename)
            if not is_valid:
                return {
                    'success' : False,
                    'error' : error_msg,
                    'vulnerabilities' : []
                }
            
            filename = CodeValidator.sanitize_filename(filename)

            vulnerabilities = []
            parse_error = None

            from src.scanner.parser import PythonParser
            parser = PythonParser()

            try:
                parsed = parser.parse(code)
            except RecursionError:
                return {
                    'success' : False,
                    'error' : 'Code is too complex or contains infinite recursion',
                    'vulnerabilities' : []
                }
            except MemoryError:
                return {
                    'success' : False,
                    'error' : 'Code requires too much memory to analyze',
                    'vulnerabilities' : []
                }
            
            if parsed.get('error'):
                parse_error = parsed['error']

            try:
                rule_vulns = self._apply_rules(code, filename)
                vulnerabilities.extend(rule_vulns)
            except Exception as e:
                logging.error(f"Error in rule-based detection: {str(e)}")

            if parsed.get('ast'):
                try:
                    ast_vulns = self._analyze_ast(parsed['ast'], code, filename)
                    vulnerabilities.extend(ast_vulns)
                except Exception as e:
                    logging.error(f"Error in AST analysis: {str(e)}")

            seen = set()
            unique_vulns = []
            for vuln in vulnerabilities:
                key = (vuln.rule_id, vuln.line, vuln.column)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)

            vulnerabilities = unique_vulns

            vulnerabilities.sort(key = lambda v: (
                -config.SEVERITY_LEVELS.get(v.severity, 0),
                v.line
            ))

            response = {
                'success' : True,
                'vulnerabilities' : [asdict(v) for v in vulnerabilities],
                'summary' : self._generate_summary(vulnerabilities),
                'metrics' : self._calculate_metrics(code, vulnerabilities)
            }

            if parse_error:
                response['warning'] = f"Partial analysis completed. Parse warning: {parse_error}"

            return response
        
        except Exception as e:
            logging.error(f"Unexpected error in analyze_code: {str(e)}")
            logging.error(traceback.format_exc())

            return{
                'success' : False,
                'error' : 'An unexpected error occurred during analysis. Please try again.',
                'vulnerabilities' : []
            }
    

    def _apply_rules(self, code: str, filename: str) -> List[Vulnerability]:
        """Apply regex-based security rules"""
        vulnerabilities = []
        lines = code.splitlines()
        
        for rule in self.rules:
            pattern = rule['pattern']
            
            # Search for pattern in code
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                line_num = code[:match.start()].count('\n') + 1
                
                # Get code snippet (3 lines of context)
                start_line = max(0, line_num - 2)
                end_line = min(len(lines), line_num + 1)
                snippet_lines = lines[start_line:end_line]
                snippet = '\n'.join(f"{start_line + i + 1}: {line}" 
                                   for i, line in enumerate(snippet_lines))
                
                vuln = Vulnerability(
                    rule_id=rule['id'],
                    name=rule['name'],
                    severity=rule['severity'],
                    message=rule['message'],
                    file=filename,
                    line=line_num,
                    column=match.start() - code.rfind('\n', 0, match.start()),
                    code_snippet=snippet,
                    cwe=rule.get('cwe', ''),
                    owasp=rule.get('owasp', ''),
                    confidence=0.9
                )
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_ast(self, tree: ast.AST, code: str, filename: str) -> List[Vulnerability]:
        """Analyze AST for security patterns"""
        vulnerabilities = []
        lines = code.splitlines()
        
        class SecurityVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    # eval() usage
                    if func_name == 'eval':
                        vuln = Vulnerability(
                            rule_id='AST_EVAL_001',
                            name='Use of eval()',
                            severity='CRITICAL',
                            message='eval() can execute arbitrary code and is a security risk',
                            file=filename,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            cwe='CWE-95',
                            confidence=1.0
                        )
                        vulnerabilities.append(vuln)
                    
                    # exec() usage
                    elif func_name == 'exec':
                        vuln = Vulnerability(
                            rule_id='AST_EXEC_001',
                            name='Use of exec()',
                            severity='CRITICAL',
                            message='exec() can execute arbitrary code',
                            file=filename,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            cwe='CWE-95',
                            confidence=1.0
                        )
                        vulnerabilities.append(vuln)
                
                self.generic_visit(node)
            
            def _get_snippet(self, lines, line_num):
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                return '\n'.join(f"{start + i + 1}: {lines[start + i]}" 
                               for i in range(end - start))
        
        visitor = SecurityVisitor()
        visitor.visit(tree)
        
        return vulnerabilities
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate summary statistics"""
        severity_counts = {}
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        return {
            'total': len(vulnerabilities),
            'by_severity': severity_counts,
            'risk_score': self._calculate_risk_score(vulnerabilities)
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0
        
        score = 0
        weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 5,
            'LOW': 2,
            'INFO': 1
        }
        
        for vuln in vulnerabilities:
            score += weights.get(vuln.severity, 0)
        
        # Cap at 100
        return min(100, score)
    
    def _calculate_metrics(self, code: str, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Calculate code metrics"""
        lines = code.splitlines()
        
        return {
            'lines_of_code': len(lines),
            'vulnerabilities_per_kloc': (len(vulnerabilities) / max(1, len(lines))) * 1000,
            'has_critical': any(v.severity == 'CRITICAL' for v in vulnerabilities)
        }