"""Unit tests for AI code verification harness."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ch08_ai_first_engineering.verification_harness import AICodeAuditor


class TestAIAuditor(unittest.TestCase):

    def test_clean_code_passes(self):
        clean_code = '''
def calculate_hash(data: str) -> str:
    """Computes sha256 hash of input data."""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()
'''
        res = AICodeAuditor.audit_source_string(clean_code)
        self.assertTrue(res["passed_quality_gate"])
        self.assertEqual(res["violations_count"], 0)

    def test_hardcoded_secret_fails(self):
        dirty_code = '''
def query_openai():
    api_key = "sk-1234567890abcdef1234567890abcdef"
    return api_key
'''
        res = AICodeAuditor.audit_source_string(dirty_code)
        self.assertFalse(res["passed_quality_gate"])
        self.assertTrue(any("secret key" in v for v in res["violations"]))

    def test_bare_except_fails(self):
        dirty_code = '''
def dangerous_handler():
    try:
        do_something()
    except:
        pass
'''
        res = AICodeAuditor.audit_source_string(dirty_code)
        self.assertFalse(res["passed_quality_gate"])
        self.assertTrue(any("Bare except" in v for v in res["violations"]))


if __name__ == "__main__":
    unittest.main()
