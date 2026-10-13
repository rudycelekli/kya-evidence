#!/usr/bin/env python3
"""Secondary, independently written KYA byte-layer implementation.

Canonicalization and hashes use only Python's standard library. Optional
Ed25519 verification uses an already installed cryptography package. This is
not an assessment engine, an external implementation, or RFC 8785 conformance.
"""

import argparse
import base64
import hashlib
import json
import math
import re
import sys
from pathlib import Path

MAX_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
FORBIDDEN = {"__proto__", "prototype", "constructor"}
SUBSET = "kya.python-byte-subset/v1"
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


class InvalidValue(ValueError):
    """Malformed or out-of-bounds input, never a positive verification."""


class UnsupportedNumber(InvalidValue):
    """A valid JS double whose canonical spelling this subset does not claim."""


def require(condition, message):
    if not condition:
        raise InvalidValue(message)


def utf16_units(value):
    return value.encode("utf-16-be", "surrogatepass")


def quote_string(value):
    """JSON.stringify string spelling, including escaped lone surrogates."""
    require(type(value) is str, "Expected a string")
    require(len(utf16_units(value)) // 2 <= MAX_BYTES, "JSON string too large")
    result = ['"']
    short = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}
    i = 0
    while i < len(value):
        char = value[i]
        code = ord(char)
        if char == '"':
            result.append('\\"')
        elif char == "\\":
            result.append("\\\\")
        elif code in short:
            result.append(short[code])
        elif code < 32:
            result.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDBFF and i + 1 < len(value) and 0xDC00 <= ord(value[i + 1]) <= 0xDFFF:
            result.append(chr(0x10000 + ((code - 0xD800) << 10) + ord(value[i + 1]) - 0xDC00))
            i += 1
        elif 0xD800 <= code <= 0xDFFF:
            result.append("\\u%04x" % code)
        else:
            result.append(char)
        i += 1
    result.append('"')
    return "".join(result)


def number_text(value):
    """Fail closed outside a deliberately small proven numeric subset.

    Safe integers, exact dyadic fractions of magnitude <= 1 with denominator
    <= 256, and signed powers 10^-1 through 10^-15 are supported. No general
    Python repr-to-ECMAScript translation or expected-vector forwarding occurs.
    """
    if type(value) is int:
        require(abs(value) <= MAX_SAFE_INTEGER, "Unsafe JSON integer")
        return str(value)
    require(type(value) is float and math.isfinite(value), "Unsafe JSON number")
    if value == 0:
        return "0"
    if value.is_integer():
        require(abs(value) <= MAX_SAFE_INTEGER, "Unsafe JSON integer")
        return str(int(value))
    sign = "-" if value < 0 else ""
    absolute = abs(value)
    for exponent in range(1, 16):
        if absolute == float("1e-%d" % exponent):
            return sign + ("0." + "0" * (exponent - 1) + "1" if exponent <= 6 else "1e-%d" % exponent)
    numerator, denominator = absolute.as_integer_ratio()
    if absolute <= 1 and denominator <= 256:
        # A binary denominator is 2^k. Multiplication by 5^k yields an exact
        # terminating decimal with at most eight fractional digits.
        exponent = denominator.bit_length() - 1
        require(denominator == 1 << exponent, "Nonbinary floating-point denominator")
        digits = str(numerator * (5 ** exponent)).rjust(exponent + 1, "0")
        return sign + digits[:-exponent] + "." + digits[-exponent:].rstrip("0")
    raise UnsupportedNumber("Noninteger double is outside the declared portable numeric subset")


def canonical(value):
    nodes = 0
    ancestors = set()

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        require(nodes <= MAX_NODES and depth <= MAX_DEPTH, "JSON resource limit")
        kind = type(item)
        if item is None:
            return "null"
        if kind is bool:
            return "true" if item else "false"
        if kind is str:
            return quote_string(item)
        if kind in (int, float):
            return number_text(item)
        require(kind in (dict, list), "Only exact JSON built-in types are supported")
        require(id(item) not in ancestors, "Cyclic JSON")
        ancestors.add(id(item))
        try:
            if kind is list:
                require(len(item) <= MAX_NODES, "JSON array too large")
                result = "[" + ",".join(visit(child, depth + 1) for child in item) + "]"
            else:
                require(all(type(key) is str and key not in FORBIDDEN for key in item), "Forbidden JSON member")
                keys = sorted(item, key=utf16_units)
                units = [utf16_units(key) for key in keys]
                require(len(set(units)) == len(units), "Duplicate UTF-16 JSON member")
                result = "{" + ",".join(quote_string(key) + ":" + visit(item[key], depth + 1) for key in keys) + "}"
        finally:
            ancestors.remove(id(item))
        require(len(result.encode("utf-16-le", "surrogatepass")) // 2 <= MAX_BYTES, "JSON value too large")
        return result

    result = visit(value, 0)
    require(len(result.encode("utf-8")) <= MAX_BYTES, "JSON byte limit")
    return result


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def parse_json(text):
    require(type(text) is str and len(text.encode("utf-8", "surrogatepass")) <= MAX_BYTES, "JSON byte limit")

    def object_pairs(pairs):
        result = {}
        seen = set()
        for key, value in pairs:
            units = utf16_units(key)
            require(key not in FORBIDDEN and units not in seen, "Duplicate or forbidden JSON member")
            seen.add(units)
            result[key] = value
        return result

    def constant(_value):
        raise InvalidValue("Nonfinite JSON constant")

    try:
        value = json.loads(text, object_pairs_hook=object_pairs, parse_constant=constant)
    except (json.JSONDecodeError, RecursionError) as error:
        raise InvalidValue("Invalid or excessively nested JSON") from error
    canonical(value)
    return value


def read_bounded(file=None):
    stream = open(file, "rb") if file is not None else sys.stdin.buffer
    try:
        data = stream.read(MAX_BYTES + 1)
    finally:
        if file is not None:
            stream.close()
    require(len(data) <= MAX_BYTES, "JSON byte limit")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise InvalidValue("Input is not UTF-8") from error


def signature_bytes(envelope, enable_crypto=True):
    """Verify the proof byte layer only; no trusting issuers or assessment."""
    require(type(envelope) is dict and set(envelope) == {"payload", "proof"}, "Invalid envelope shape")
    payload, proof = envelope["payload"], envelope["proof"]
    require(type(payload) is dict and payload.get("schema") == "kya.evidence/v1", "Unsupported payload domain")
    require(type(proof) is dict and set(proof) == {"algorithm", "keyId", "publicKey", "signature"}, "Invalid proof shape")
    require(proof["algorithm"] == "Ed25519", "Unsupported proof algorithm")
    pem, encoded = proof["publicKey"], proof["signature"]
    require(type(pem) is str and len(pem) <= 2000, "Invalid public key")
    match = re.fullmatch(r"-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END PUBLIC KEY-----\r?\n?", pem)
    require(match is not None, "Expected public SPKI PEM only")
    try:
        der = base64.b64decode(re.sub(r"[\r\n]", "", match.group(1)), validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise InvalidValue("Invalid PEM base64") from error
    require(len(der) == 44 and der.startswith(SPKI_ED25519_PREFIX), "Expected Ed25519 SPKI key")
    require(type(proof["keyId"]) is str and hashlib.sha256(der).hexdigest() == proof["keyId"], "Proof key fingerprint differs")
    require(type(encoded) is str and re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded) is not None, "Invalid signature encoding")
    signature = base64.urlsafe_b64decode(encoded + "==")
    require(len(signature) == 64 and base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") == encoded, "Noncanonical signature encoding")
    signing_input = "kya.evidence/v1\n" + canonical(payload)
    result = {"signingInput": signing_input, "keyId": proof["keyId"], "authenticatedIssuer": False, "semanticReceiptValidation": False}
    if not enable_crypto:
        return dict(result, status="unavailable", verified=False, reason="Cryptographic backend explicitly disabled")
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    except ImportError:
        return dict(result, status="unavailable", verified=False, reason="Optional cryptography package is not installed")
    try:
        Ed25519PublicKey.from_public_bytes(der[-32:]).verify(signature, signing_input.encode("utf-8"))
    except InvalidSignature as error:
        raise InvalidValue("Ed25519 signature verification failed") from error
    except UnsupportedAlgorithm:
        return dict(result, status="unavailable", verified=False, reason="Installed backend does not support Ed25519")
    return dict(result, status="verified", verified=True, backend="cryptography", backendVersion=cryptography.__version__)


def check_vectors(vectors, enable_crypto=True):
    require(type(vectors) is dict and vectors.get("schema") == "kya.golden-vectors/v1", "Unsupported vector schema")
    cases = vectors.get("cases")
    require(type(cases) is list and 0 < len(cases) <= 256, "Invalid vector cases")
    for index, case in enumerate(cases):
        require(type(case) is dict and set(case) == {"input", "canonical", "sha256"}, "Invalid vector case")
        actual = canonical(case["input"])
        require(actual == case["canonical"], "Canonical mismatch at case %d" % index)
        require(hashlib.sha256(actual.encode("utf-8")).hexdigest() == case["sha256"], "Hash mismatch at case %d" % index)
    vector = vectors.get("signature")
    require(type(vector) is dict, "Missing signature vector")
    envelope = vector.get("envelope")
    require(digest(envelope) == vector.get("envelopeDigest"), "Envelope digest differs")
    verified = signature_bytes(envelope, enable_crypto)
    require(verified["signingInput"] == vector.get("signingInput"), "Reconstructed signing input differs")
    return {"schema": "kya.python-vector-check/v1", "subset": SUBSET, "status": "passed" if verified["verified"] else "partial", "canonicalCases": len(cases), "signature": {key: value for key, value in verified.items() if key != "signingInput"}, "externalIndependence": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("canonical", help="Canonicalize bounded JSON from stdin")
    checker = commands.add_parser("check-vectors", help="Reconstruct and verify vector bytes and hashes")
    checker.add_argument("file")
    checker.add_argument("--no-crypto", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = parse_json(read_bounded(None if args.command == "canonical" else args.file))
        result = {"schema": "kya.python-canonical/v1", "subset": SUBSET, "canonical": canonical(value), "sha256": digest(value)} if args.command == "canonical" else check_vectors(value, not args.no_crypto)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except UnsupportedNumber as error:
        print(json.dumps({"status": "unsupported", "subset": SUBSET, "reason": str(error)}))
        return 2
    except (InvalidValue, OSError, UnicodeError, RecursionError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)[:512]}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
