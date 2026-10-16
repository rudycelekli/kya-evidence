"""Standard-library adversarial checks for the secondary byte implementation."""
import copy
import json
import runpy
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = runpy.run_path(str(HERE / "kya_portability.py"))
canonical = MODULE["canonical"]
digest = MODULE["digest"]
parse_json = MODULE["parse_json"]
check_vectors = MODULE["check_vectors"]
InvalidValue = MODULE["InvalidValue"]
incident_bytes = MODULE["incident_bytes"]
check_incident_vectors = MODULE["check_incident_vectors"]
UnsupportedNumber = MODULE["UnsupportedNumber"]
VECTORS = json.loads((HERE.parent.parent / "evidence/golden-vectors.json").read_text())


class PortableBytes(unittest.TestCase):
    def test_all_published_canonical_bytes_and_hashes(self):
        result = check_vectors(VECTORS, False)
        self.assertEqual(result["canonicalCases"], 6)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["signature"]["verified"])

    def test_optional_existing_crypto_is_explicit(self):
        result = check_vectors(VECTORS)
        self.assertIn(result["status"], ("passed", "partial"))
        self.assertEqual(result["status"] == "passed", result["signature"]["verified"])
        self.assertFalse(result["signature"]["authenticatedIssuer"])

    def test_corrupted_expected_canonical_is_detected(self):
        changed = copy.deepcopy(VECTORS)
        changed["cases"][0]["canonical"] = "0"
        with self.assertRaisesRegex(InvalidValue, "Canonical mismatch"):
            check_vectors(changed, False)

    def test_corrupted_expected_hash_is_detected(self):
        changed = copy.deepcopy(VECTORS)
        changed["cases"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(InvalidValue, "Hash mismatch"):
            check_vectors(changed, False)

    def test_signing_input_is_rebuilt_from_payload(self):
        changed = copy.deepcopy(VECTORS)
        changed["signature"]["signingInput"] += " "
        with self.assertRaisesRegex(InvalidValue, "signing input"):
            check_vectors(changed, False)

    def test_envelope_bytes_bind_digest(self):
        changed = copy.deepcopy(VECTORS)
        changed["signature"]["envelope"]["payload"]["outcome"] = "fail"
        with self.assertRaisesRegex(InvalidValue, "Envelope digest"):
            check_vectors(changed, False)

    def test_crypto_detects_a_forged_signature_despite_updated_checksum(self):
        if not check_vectors(VECTORS)["signature"]["verified"]:
            self.skipTest("Optional cryptographic backend unavailable; never reported as verified")
        changed = copy.deepcopy(VECTORS)
        proof = changed["signature"]["envelope"]["proof"]
        proof["signature"] = ("A" if proof["signature"][0] != "A" else "B") + proof["signature"][1:]
        changed["signature"]["envelopeDigest"] = digest(changed["signature"]["envelope"])
        with self.assertRaisesRegex(InvalidValue, "signature verification"):
            check_vectors(changed)

    def test_utf16_order_is_not_unicode_scalar_order(self):
        self.assertEqual(canonical({"\ue000": 2, "\U00010000": 1}), '{"\U00010000":1,"\ue000":2}')

    def test_lone_surrogates_and_paired_units(self):
        self.assertEqual(canonical("\ud800x\udfff"), '"\\ud800x\\udfff"')
        self.assertEqual(canonical("\ud83d\ude00"), '"😀"')
        with self.assertRaisesRegex(InvalidValue, "Duplicate UTF-16"):
            canonical({"😀": 1, "\ud83d\ude00": 2})

    def test_string_escaping_without_unicode_normalization(self):
        self.assertEqual(canonical('"\\\b\t\n\f\r\x00/\u2028'), '"\\"\\\\\\b\\t\\n\\f\\r\\u0000/\u2028"')
        self.assertNotEqual(digest("é"), digest("e\u0301"))

    def test_numeric_subset_and_signed_zero(self):
        self.assertEqual(canonical([-0.0, 0.25, -0.125, 1e-6, 1e-7, 1e-10]), '[0,0.25,-0.125,0.000001,1e-7,1e-10]')
        self.assertEqual(canonical(9_007_199_254_740_991), '9007199254740991')
        for value in [0.3, 1.23456789, 5e-324]:
            with self.assertRaises(UnsupportedNumber):
                canonical(value)
        for value in [9_007_199_254_740_992, float("nan"), float("inf")]:
            with self.assertRaises(InvalidValue):
                canonical(value)

    def test_duplicate_escaped_and_prototype_members(self):
        for text in ['{"x":1,"x":2}', '{"x":1,"\\u0078":2}', '{"__proto__":1}', '{"constructor":1}']:
            with self.assertRaises(InvalidValue):
                parse_json(text)

    def test_nonjson_and_resource_limits(self):
        for text in ['NaN', 'Infinity', '1e999', '0 true', '[' * 40 + '0' + ']' * 40]:
            with self.assertRaises(InvalidValue):
                parse_json(text)
        with self.assertRaises(InvalidValue):
            parse_json('"' + 'x' * 1_048_576 + '"')
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(InvalidValue):
            canonical(cycle)

    def test_arbitrary_python_types_and_properties_are_not_consumed(self):
        class Custom(dict):
            def __getitem__(self, key):
                self.fail("Must not consume custom mapping")
        with self.assertRaises(InvalidValue):
            canonical(Custom(x=1))
        with self.assertRaises(InvalidValue):
            canonical((1, 2))


class IncidentBytes(unittest.TestCase):
    BLOCK = VECTORS["incidents"]
    BY_ID = {vector["id"]: vector for vector in BLOCK["vectors"]}

    def test_every_vector_matches_its_javascript_expectation(self):
        results = check_incident_vectors(self.BLOCK)
        self.assertEqual(len(results), len(self.BLOCK["vectors"]))
        if check_vectors(VECTORS)["signature"]["verified"]:
            for item in results:
                self.assertEqual(item["actual"], "accepted" if item["expect"] == "accept" else "rejected", item["id"])

    def test_required_vector_coverage(self):
        kinds = {v["envelope"]["payload"].get("kind") for v in self.BLOCK["vectors"] if v["expect"] == "accept"}
        self.assertEqual(kinds, {"report", "resolution", "appeal"})
        for name in ("wrong-kind", "wrong-severity", "report-with-ref", "resolution-null-ref", "extra-field", "bad-timestamp-format", "tampered-payload", "altered-signature", "noncanonical-signature-encoding", "evidence-domain-signature"):
            self.assertEqual(self.BY_ID[name]["expect"], "reject", name)

    def test_stdlib_mode_rejects_shape_and_never_claims_signatures(self):
        results = {item["id"]: item for item in check_incident_vectors(self.BLOCK, False)}
        for vector in self.BLOCK["vectors"]:
            item = results[vector["id"]]
            if vector["expect"] == "reject" and vector["stage"] == "shape":
                self.assertEqual((item["actual"], item["stage"]), ("rejected", "shape"), vector["id"])
            else:
                self.assertEqual(item["actual"], "unverified", vector["id"])
        self.assertEqual(check_vectors(VECTORS, False)["status"], "partial")

    def test_signature_stage_failures_need_crypto_and_are_signature_stage(self):
        if not check_vectors(VECTORS)["signature"]["verified"]:
            self.skipTest("Optional cryptographic backend unavailable; never reported as verified")
        for vector in self.BLOCK["vectors"]:
            if vector["stage"] == "signature":
                with self.assertRaises(InvalidValue) as caught:
                    incident_bytes(vector["envelope"])
                self.assertEqual(caught.exception.stage, "signature", vector["id"])

    def test_mismatched_expectation_or_digest_fails_the_check(self):
        changed = copy.deepcopy(self.BLOCK)
        changed["vectors"][0]["expect"] = "reject"
        changed["vectors"][0]["stage"] = "shape"
        with self.assertRaises(InvalidValue):
            check_incident_vectors(changed, False)
        changed = copy.deepcopy(self.BLOCK)
        changed["vectors"][0]["envelope"]["payload"]["severity"] = "low"
        with self.assertRaisesRegex(InvalidValue, "envelope digest"):
            check_incident_vectors(changed, False)

    def test_shape_rules_are_strict(self):
        good = copy.deepcopy(self.BY_ID["resolution"]["envelope"])
        for key, value in [("refId", good["payload"]["id"]), ("refId", None), ("kind", "Report"), ("severity", ["low"]), ("reportedAt", "2026-10-14T12:00:00.000+00:00"), ("reportedAt", "٢026-10-14T12:00:00.000Z"), ("id", "x\n"), ("detailsDigest", "A" * 64)]:
            changed = copy.deepcopy(good)
            changed["payload"][key] = value
            with self.assertRaises(InvalidValue, msg=key):
                incident_bytes(changed, False)
        for date, ok in [("2024-02-29", True), ("2023-02-29", False), ("1900-02-29", False), ("2000-02-29", True), ("0000-02-29", True)]:
            changed = copy.deepcopy(good)
            changed["payload"]["reportedAt"] = date + "T00:00:00.000Z"
            if ok:
                incident_bytes(changed, False)
            else:
                with self.assertRaises(InvalidValue):
                    incident_bytes(changed, False)

    def test_evidence_envelope_is_not_an_incident_and_vice_versa(self):
        with self.assertRaises(InvalidValue):
            incident_bytes(VECTORS["signature"]["envelope"], False)
        with self.assertRaises(InvalidValue):
            MODULE["signature_bytes"](self.BY_ID["report"]["envelope"], False)

    def test_oversized_integer_literal_is_a_structured_failure_not_a_traceback(self):
        import subprocess
        import sys
        text = '{"a":' + "1" * 4301 + "}"
        with self.assertRaises(InvalidValue):
            parse_json(text)
        done = subprocess.run([sys.executable, str(HERE / "kya_portability.py"), "canonical"], input=text.encode(), capture_output=True)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout)["status"], "failed")
        self.assertNotIn(b"Traceback", done.stderr)


class PublicKeyStrictness(unittest.TestCase):
    """The core refuses non-canonical key spellings and small-order or non-canonical points; so must this checker."""
    HEAD, TAIL = "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
    PREFIX = bytes.fromhex("302a300506032b6570032100")
    ZERO_SIG = "AQ" + "A" * 84

    def envelope(self, pem=None, der=None, signature=None):
        import hashlib
        env = copy.deepcopy(VECTORS["signature"]["envelope"])
        if pem is not None:
            env["proof"]["publicKey"] = pem
            env["proof"]["keyId"] = hashlib.sha256(der).hexdigest()
        if signature is not None:
            env["proof"]["signature"] = signature
        return env

    def good(self):
        import base64
        pem = VECTORS["signature"]["envelope"]["proof"]["publicKey"]
        body = pem.split("\n")[1]
        return pem, body, base64.b64decode(body)

    def pem_of(self, der, width=60):
        import base64
        text = base64.b64encode(der).decode()
        lines = [text[i:i + width] for i in range(0, len(text), width)]
        return self.HEAD + "\n" + "\n".join(lines) + "\n" + self.TAIL + "\n"

    def refused(self, env, pattern):
        for crypto in (False, True):
            with self.assertRaisesRegex(InvalidValue, pattern):
                MODULE["signature_bytes"](env, crypto)

    def test_canonical_vector_key_is_accepted(self):
        pem, _, der = self.good()
        self.assertEqual(self.pem_of(der), pem)
        self.assertEqual(MODULE["signature_bytes"](self.envelope(), False)["status"], "unavailable")

    def test_crlf_pem_is_refused(self):
        pem, _, der = self.good()
        self.refused(self.envelope(pem.replace("\n", "\r\n"), der), "canonical")

    def test_rewrapped_pem_lines_are_refused(self):
        _, _, der = self.good()
        for width in (20, 30, 40, 59):
            self.refused(self.envelope(self.pem_of(der, width), der), "canonical")

    def test_missing_trailing_newline_is_refused(self):
        pem, _, der = self.good()
        self.refused(self.envelope(pem[:-1], der), "canonical")

    def test_blank_line_in_base64_is_refused(self):
        _, body, der = self.good()
        self.refused(self.envelope(self.HEAD + "\n\n" + body + "\n" + self.TAIL + "\n", der), "canonical")
        self.refused(self.envelope(self.HEAD + "\n" + body + "\n\n" + self.TAIL + "\n", der), "canonical")

    def test_non_canonical_trailing_base64_bits_are_refused(self):
        _, body, der = self.good()
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        sloppy = body[:58] + alphabet[(alphabet.index(body[58]) + 1) % 64] + "="
        self.refused(self.envelope(self.HEAD + "\n" + sloppy + "\n" + self.TAIL + "\n", der), "canonical")

    def test_long_form_der_length_is_refused(self):
        _, _, der = self.good()
        longer = bytes([0x30, 0x81, der[1]]) + der[2:]
        self.refused(self.envelope(self.pem_of(longer), longer), "SPKI|canonical")

    def test_trailing_zero_bytes_after_the_spki_are_refused(self):
        _, _, der = self.good()
        for extra in (1, 2, 8):
            padded = der + bytes(extra)
            self.refused(self.envelope(self.pem_of(padded), padded), "SPKI|canonical")

    def test_identity_point_key_with_signature_01_then_zeros_is_refused(self):
        der = self.PREFIX + bytes([1]) + bytes(31)
        self.refused(self.envelope(self.pem_of(der), der, self.ZERO_SIG), "small-order")

    def test_every_small_order_point_is_refused(self):
        for raw in (
            "01" + "00" * 31, "ec" + "ff" * 30 + "7f", "00" * 32, "00" * 31 + "80",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ):
            der = self.PREFIX + bytes.fromhex(raw)
            self.refused(self.envelope(self.pem_of(der), der, self.ZERO_SIG), "small-order")

    def test_non_canonical_y_encodings_are_refused(self):
        for raw in (
            "ed" + "ff" * 30 + "7f", "ee" + "ff" * 30 + "7f", "ee" + "ff" * 30 + "ff",
            "01" + "00" * 30 + "80", "ff" * 32,
        ):
            der = self.PREFIX + bytes.fromhex(raw)
            self.refused(self.envelope(self.pem_of(der), der, self.ZERO_SIG), "(?i)non-canonical")

    def test_off_curve_point_is_refused(self):
        for y in range(2, 40):
            der = self.PREFIX + y.to_bytes(32, "little")
            try:
                MODULE["signature_bytes"](self.envelope(self.pem_of(der), der, self.ZERO_SIG), False)
            except InvalidValue as error:
                if "not on the curve" in str(error):
                    return
        self.fail("expected at least one small y value to be off the curve")


if __name__ == "__main__":
    unittest.main()
