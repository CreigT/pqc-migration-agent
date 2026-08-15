import unittest

from src.main import DocumentBlock, find_crypto_references


class DetectionTests(unittest.TestCase):
    def detect(self, text):
        return find_crypto_references([DocumentBlock(text=text, source_type="txt", line=1)], 60)

    def test_detects_weak_rsa(self):
        findings = self.detect("Legacy server uses RSA-1024 for signing.")
        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("rsa-weak-key", rule_ids)

    def test_detects_md5_as_critical(self):
        findings = self.detect("The old integration validates files with MD5.")
        md5 = next(finding for finding in findings if finding["rule_id"] == "md5")
        self.assertEqual(md5["risk"], "critical")
        self.assertFalse(md5["post_quantum_relevant"])

    def test_detects_ecdsa_as_post_quantum_relevant(self):
        findings = self.detect("Certificates currently use ECDSA.")
        ecdsa = next(finding for finding in findings if finding["rule_id"] == "ecdsa")
        self.assertTrue(ecdsa["post_quantum_relevant"])

    def test_clean_text_has_no_findings(self):
        findings = self.detect("This document contains general inventory notes only.")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
