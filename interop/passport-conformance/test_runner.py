import sys
import unittest
from run import run_case

VECTOR = {"id": "fixture", "operation": "passport-history", "inputs": {}, "expected": {"status": "reject"}}
ENVELOPE = '{"schema":"kya.passport-conformance-result/v1","operation":"passport-history","status":'


class RunnerTests(unittest.TestCase):
    def candidate(self, source):
        return run_case(VECTOR, [sys.executable, "-c", source])[0]

    def test_valid_refusal_requires_a_zero_exit_and_an_exact_envelope(self):
        body = ENVELOPE + '"reject"}'
        self.assertEqual(self.candidate(f"print({body!r})"), "pass")
        self.assertEqual(self.candidate("raise SystemExit(1)"), "fail")

    def test_unsupported_does_not_count_as_refusal(self):
        body = ENVELOPE + '"unsupported"}'
        self.assertEqual(self.candidate(f"print({body!r})"), "unsupported")

    def test_duplicate_keys_and_extra_fields_fail(self):
        duplicate = ENVELOPE + '"accept","status":"reject"}'
        extra = ENVELOPE + '"reject","value":null}'
        for body in (duplicate, extra):
            self.assertEqual(self.candidate(f"print({body!r})"), "fail")


if __name__ == "__main__":
    unittest.main()
