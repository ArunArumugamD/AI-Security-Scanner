import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.analyzer import SecurityAnalyzer

class TestSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer()
    
    def test_sql_injection_detection(self):
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
        '''
        results = self.analyzer.analyze_code(code)
        self.assertTrue(results['success'])
        self.assertGreater(len(results['vulnerabilities']), 0)
        
        # Check if SQL injection was detected
        vuln_types = [v['name'] for v in results['vulnerabilities']]
        self.assertTrue(any('SQL' in name for name in vuln_types))
    
    def test_hardcoded_secret_detection(self):
        code = '''
API_KEY = "sk-1234567890abcdef"
password = "admin123"
        '''
        results = self.analyzer.analyze_code(code)
        self.assertTrue(results['success'])
        self.assertGreater(len(results['vulnerabilities']), 0)
    
    def test_safe_code(self):
        code = '''
def add_numbers(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
        '''
        results = self.analyzer.analyze_code(code)
        self.assertTrue(results['success'])
        self.assertEqual(len(results['vulnerabilities']), 0)

if __name__ == '__main__':
    unittest.main()