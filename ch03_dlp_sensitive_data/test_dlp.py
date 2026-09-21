"""Unit tests for DLP scanning, entropy calculation, and token redaction."""
import unittest
from .dlp_scanner import DLPScanner, SensitiveType, shannon_entropy
from .pii_redactor import PIIRedactor


class TestDLPAndRedactor(unittest.TestCase):

    def setUp(self):
        self.scanner = DLPScanner()
        self.redactor = PIIRedactor()

    def test_shannon_entropy(self):
        # Repetitive low entropy
        low = shannon_entropy("aaaaaaaaaaaa")
        self.assertAlmostEqual(low, 0.0, places=2)

        # High entropy random string
        high = shannon_entropy("k9#mP$2vL!9xQ@4z")
        self.assertGreater(high, 3.5)

    def test_email_and_phone_detection(self):
        sample = "Contact John Doe at john.doe@cybercorp.internal or +91 9876543210 for security access."
        matches = self.scanner.scan(sample)
        types = [m.sensitive_type for m in matches]
        self.assertIn(SensitiveType.PII_EMAIL, types)

    def test_aws_credential_detection(self):
        sample = "Deploy using AWS key AKIAIOSFODNN7EXAMPLE for S3 backup."
        matches = self.scanner.scan(sample)
        self.assertTrue(any(m.sensitive_type == SensitiveType.AWS_CREDENTIAL for m in matches))

    def test_aadhaar_pan_detection(self):
        sample = "Employee ID verification: Aadhaar 3456 7890 1234 and PAN ABCDE1234F."
        matches = self.scanner.scan(sample)
        types = [m.sensitive_type for m in matches]
        self.assertIn(SensitiveType.PII_AADHAAR, types)
        self.assertIn(SensitiveType.PII_PAN, types)

    def test_pii_redaction_and_restoration(self):
        raw_text = "Send medical summary for patient to doctor@clinic.org with token sk-99887766554433221100aa."
        redacted, token_map = self.redactor.redact(raw_text)
        self.assertNotIn("doctor@clinic.org", redacted)
        self.assertIn("[PII_EMAIL_", redacted)

        restored = self.redactor.restore(redacted)
        self.assertEqual(restored, raw_text)


if __name__ == "__main__":
    unittest.main()
