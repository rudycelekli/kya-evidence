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


if __name__ == "__main__":
    unittest.main()
