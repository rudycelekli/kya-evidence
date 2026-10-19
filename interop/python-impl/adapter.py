#!/usr/bin/env python3
"""KYA contract version 2, Python 3 implementation of six operations.

Standard library only. Written from docs/SPECIFICATION.md, docs/SCORING.md,
docs/IMPLEMENTERS-GUIDE.md, interop/impl-contract/README.md and the ADRs. Operations
implemented: canonicalize, digest, verify-envelope, compare, assess, currency. Every other
operation (verify-credential, verify-score-card, compare-score-cards) answers unsupported.

Ed25519 verification is implemented here from RFC 8032 with Python integers; it is not
constant time and must not be used to sign or to verify secrets.
"""
import sys
import re
import json
import hashlib
import base64
import binascii
import calendar
import time

MAX_INPUT_BYTES = 1048576
MAX_DEPTH = 32
MAX_VALUES = 100000
MAX_STRING_UNITS = 1048576
MAX_CANON_BYTES = 1048576
FORBIDDEN_NAMES = ("__proto__", "prototype", "constructor")


class Refusal(Exception):
    pass


def refuse(msg):
    raise Refusal(msg)


# ---------------------------------------------------------------------------
# UTF-16 helpers
# ---------------------------------------------------------------------------

def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def utf16_len(s):
    return len(utf16_key(s)) // 2


def has_surrogate(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            return True
    return False


# ---------------------------------------------------------------------------
# Strict JSON parser
# ---------------------------------------------------------------------------

_WS = " \t\n\r"
_NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_CHUNK_RE = re.compile(r'[^"\\\x00-\x1f]*')
_HEX4_RE = re.compile(r"[0-9a-fA-F]{4}")
_ESC = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class _Parser(object):
    def __init__(self, text):
        self.t = text
        self.i = 0
        self.n = len(text)
        self.count = 0

    def skip_ws(self):
        t = self.t
        i = self.i
        n = self.n
        while i < n and t[i] in _WS:
            i += 1
        self.i = i

    def bump(self):
        self.count += 1
        if self.count > MAX_VALUES:
            refuse("too many values")

    def parse_document(self):
        self.skip_ws()
        v = self.parse_value(0)
        self.skip_ws()
        if self.i != self.n:
            refuse("text after the value")
        return v

    def parse_value(self, depth):
        if depth > MAX_DEPTH:
            refuse("too deep")
        if self.i >= self.n:
            refuse("unexpected end")
        c = self.t[self.i]
        if c == "{":
            return self.parse_object(depth)
        if c == "[":
            return self.parse_array(depth)
        if c == '"':
            self.bump()
            return self.parse_string()
        if c == "-" or ("0" <= c <= "9"):
            self.bump()
            return self.parse_number()
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.t.startswith(lit, self.i):
                self.i += len(lit)
                self.bump()
                return val
        refuse("unexpected character")

    def parse_number(self):
        m = _NUM_RE.match(self.t, self.i)
        if not m:
            refuse("bad number")
        lit = m.group(0)
        self.i = m.end()
        f = float(lit)
        if f != f or f in (float("inf"), float("-inf")):
            refuse("number is not finite")
        if f == int(f):
            iv = int(f)
            if abs(iv) > 9007199254740991:
                refuse("integer beyond the safe range")
            return iv
        return f

    def parse_string(self):
        # self.i is at the opening quote
        t = self.t
        self.i += 1
        parts = []
        escaped_unicode = False
        while True:
            m = _CHUNK_RE.match(t, self.i)
            if m.end() > self.i:
                parts.append(m.group(0))
                self.i = m.end()
            if self.i >= self.n:
                refuse("unterminated string")
            c = t[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                if self.i + 1 >= self.n:
                    refuse("bad escape")
                e = t[self.i + 1]
                if e == "u":
                    h = _HEX4_RE.match(t, self.i + 2)
                    if not h:
                        refuse("bad unicode escape")
                    parts.append(chr(int(h.group(0), 16)))
                    escaped_unicode = True
                    self.i += 6
                elif e in _ESC:
                    parts.append(_ESC[e])
                    self.i += 2
                else:
                    refuse("bad escape")
            else:
                refuse("control character in string")
        s = "".join(parts)
        if escaped_unicode and has_surrogate(s):
            # a high surrogate directly followed by a low one is a pair
            s = s.encode("utf-16-be", "surrogatepass").decode("utf-16-be", "surrogatepass")
        if len(s) > MAX_STRING_UNITS:
            refuse("string too long")
        if len(s) > MAX_STRING_UNITS // 2 and utf16_len(s) > MAX_STRING_UNITS:
            refuse("string too long")
        return s

    def parse_array(self, depth):
        self.bump()
        self.i += 1
        out = []
        self.skip_ws()
        if self.i < self.n and self.t[self.i] == "]":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            out.append(self.parse_value(depth + 1))
            self.skip_ws()
            if self.i >= self.n:
                refuse("unterminated array")
            c = self.t[self.i]
            self.i += 1
            if c == ",":
                continue
            if c == "]":
                return out
            refuse("bad array")

    def parse_object(self, depth):
        self.bump()
        self.i += 1
        out = {}
        self.skip_ws()
        if self.i < self.n and self.t[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            if self.i >= self.n or self.t[self.i] != '"':
                refuse("member name expected")
            name = self.parse_string()
            if name in FORBIDDEN_NAMES:
                refuse("forbidden member name")
            if name in out:
                refuse("duplicate member")
            self.skip_ws()
            if self.i >= self.n or self.t[self.i] != ":":
                refuse("colon expected")
            self.i += 1
            self.skip_ws()
            out[name] = self.parse_value(depth + 1)
            self.skip_ws()
            if self.i >= self.n:
                refuse("unterminated object")
            c = self.t[self.i]
            self.i += 1
            if c == ",":
                continue
            if c == "}":
                return out
            refuse("bad object")


def parse_strict(text):
    if has_surrogate(text):
        refuse("unpaired surrogate in text")
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        refuse("text too long")
    return _Parser(text).parse_document()


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------

def es_number(f):
    """ECMAScript Number::toString for a finite non-integer double."""
    neg = f < 0
    s = repr(abs(f))
    if "e" in s:
        m, e = s.split("e")
        exp = int(e)
    else:
        m, exp = s, 0
    if "." in m:
        ip, fp = m.split(".")
    else:
        ip, fp = m, ""
    digits = ip + fp
    n = len(ip) + exp
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        sign = "+" if e >= 0 else "-"
        if k == 1:
            out = digits + "e" + sign + str(abs(e))
        else:
            out = digits[0] + "." + digits[1:] + "e" + sign + str(abs(e))
    return ("-" + out) if neg else out


def _canon_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 8:
            out.append("\\b")
        elif o == 12:
            out.append("\\f")
        elif o == 10:
            out.append("\\n")
        elif o == 13:
            out.append("\\r")
        elif o == 9:
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif type(v) is int:
        out.append(str(v))
    elif type(v) is float:
        out.append(es_number(v))
    elif type(v) is str:
        out.append(_canon_string(v))
    elif type(v) is list:
        out.append("[")
        first = True
        for x in v:
            if not first:
                out.append(",")
            first = False
            _canon(x, out)
        out.append("]")
    elif type(v) is dict:
        out.append("{")
        first = True
        for k in sorted(v.keys(), key=utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_canon_string(k))
            out.append(":")
            _canon(v[k], out)
        out.append("}")
    else:
        refuse("unsupported value")


def canonical(v):
    out = []
    _canon(v, out)
    text = "".join(out)
    if len(text.encode("utf-8")) > MAX_CANON_BYTES:
        refuse("canonical form too long")
    return text


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Field grammars
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]*")
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z")
_CTRL_RE = re.compile("[\x00-\x1f\x7f]")


def is_obj(v):
    return type(v) is dict


def exact(v, keys):
    return is_obj(v) and set(v.keys()) == set(keys)


def is_id(v):
    return type(v) is str and 1 <= len(v) <= 128 and _ID_RE.fullmatch(v) is not None


def is_text(v, maxlen=512):
    return (type(v) is str and 1 <= utf16_len(v) <= maxlen and _CTRL_RE.search(v) is None)


def is_hash(v):
    return type(v) is str and _HASH_RE.fullmatch(v) is not None


def _leap(y):
    return (y % 4 == 0 and y % 100 != 0) or y % 400 == 0


def is_ts(v):
    if type(v) is not str:
        return False
    m = _TS_RE.fullmatch(v)
    if not m:
        return False
    y, mo, d, h, mi, s, ms = [int(g) for g in m.groups()]
    if mo < 1 or mo > 12 or d < 1 or h > 23 or mi > 59 or s > 59:
        return False
    dim = [31, 29 if _leap(y) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return d <= dim


def is_int(v, lo, hi):
    return type(v) is int and lo <= v <= hi


def is_num(v, lo, hi):
    return type(v) in (int, float) and lo <= v <= hi


def unique_list(v, check, maxlen):
    if type(v) is not list or len(v) > maxlen:
        return False
    for x in v:
        if not check(x):
            return False
    return len(set(v)) == len(v)


# ---------------------------------------------------------------------------
# Record validators (return True when the record satisfies its field rules)
# ---------------------------------------------------------------------------

def valid_manifest(m):
    if not exact(m, ["schema", "agent", "principal", "system", "scope", "issuedAt", "expiresAt"]):
        return False
    if m["schema"] != "kya.manifest/v1":
        return False
    a = m["agent"]
    if not exact(a, ["id", "name", "version"]):
        return False
    if not (is_id(a["id"]) and is_text(a["name"]) and is_text(a["version"], 128)):
        return False
    p = m["principal"]
    if not is_obj(p) or not set(p.keys()) in (set(["id"]), set(["id", "accountableParty"])):
        return False
    if not is_id(p["id"]):
        return False
    if "accountableParty" in p:
        ap = p["accountableParty"]
        if not exact(ap, ["kind", "ref"]):
            return False
        if ap["kind"] not in ("natural-person", "legal-entity"):
            return False
        if not is_id(ap["ref"]) or ap["ref"].lower() == a["id"].lower():
            return False
    s = m["system"]
    if not exact(s, ["harness", "harnessVersion", "model", "artifactDigest", "configDigest", "tools"]):
        return False
    if not (is_text(s["harness"], 128) and is_text(s["harnessVersion"], 128) and is_text(s["model"], 128)):
        return False
    if not (is_hash(s["artifactDigest"]) and is_hash(s["configDigest"])):
        return False
    sc = m["scope"]
    if not exact(sc, ["id", "purpose", "permissions", "forbidden", "approvalRequired"]):
        return False
    if not (is_id(sc["id"]) and is_text(sc["purpose"])):
        return False
    for k in ("permissions", "forbidden", "approvalRequired"):
        if not unique_list(sc[k], is_id, 256):
            return False
    perms = set(sc["permissions"])
    if perms & set(sc["forbidden"]):
        return False
    if not set(sc["approvalRequired"]) <= perms:
        return False
    tools = s["tools"]
    if type(tools) is not list or len(tools) > 128:
        return False
    seen = set()
    for t in tools:
        if not exact(t, ["id", "version", "permissions"]):
            return False
        if not (is_id(t["id"]) and is_text(t["version"], 128)):
            return False
        if t["id"] in seen:
            return False
        seen.add(t["id"])
        if not unique_list(t["permissions"], is_id, 256):
            return False
        if not set(t["permissions"]) <= perms:
            return False
    if not (is_ts(m["issuedAt"]) and is_ts(m["expiresAt"])):
        return False
    return m["expiresAt"] > m["issuedAt"]


DIMENSIONS = ("identity", "authority", "security", "reliability", "accountability", "operations")


def valid_profile(p):
    if not exact(p, ["schema", "id", "version", "title", "checks"]):
        return False
    if p["schema"] != "kya.profile/v1":
        return False
    if not (is_id(p["id"]) and is_text(p["version"], 64) and is_text(p["title"])):
        return False
    cs = p["checks"]
    if type(cs) is not list or not 1 <= len(cs) <= 256:
        return False
    seen = set()
    for c in cs:
        if not exact(c, ["id", "dimension", "title", "weight", "critical"]):
            return False
        if not is_id(c["id"]) or c["id"] in seen:
            return False
        seen.add(c["id"])
        if c["dimension"] not in DIMENSIONS or not is_text(c["title"]):
            return False
        if not is_int(c["weight"], 1, 100000):
            return False
        if type(c["critical"]) is not bool:
            return False
    return True


def valid_policy(p):
    if type(p) is not dict:
        return False
    required = ["schema", "id", "scopeId", "profileDigest", "minCoverage", "minIndependentCoverage",
                "minScore", "maxEvidenceAgeSeconds", "allowedSources", "revokedKeyIds",
                "revokedSubjectDigests", "revokedEvidenceIds", "trustedKeys"]
    optional = ["maxAssessmentAgeSeconds", "requirePrincipalBinding", "mandatoryMinimums"]
    keys = set(p.keys())
    if not set(required) <= keys or not keys <= set(required + optional):
        return False
    if p["schema"] != "kya.policy/v1":
        return False
    if not (is_id(p["id"]) and is_id(p["scopeId"]) and is_hash(p["profileDigest"])):
        return False
    if not (is_num(p["minCoverage"], 0, 1) and is_num(p["minIndependentCoverage"], 0, 1)):
        return False
    if not is_int(p["minScore"], 0, 1000):
        return False
    if not is_int(p["maxEvidenceAgeSeconds"], 1, 31536000):
        return False
    if "maxAssessmentAgeSeconds" in p and not is_int(p["maxAssessmentAgeSeconds"], 1, 31536000):
        return False
    if not unique_list(p["allowedSources"], lambda x: x in ("runtime", "fixture", "declaration"), 3):
        return False
    if "requirePrincipalBinding" in p and type(p["requirePrincipalBinding"]) is not bool:
        return False
    if "mandatoryMinimums" in p:
        mm = p["mandatoryMinimums"]
        if type(mm) is not list or not 1 <= len(mm) <= 256:
            return False
        seen_min = set()
        for e in mm:
            if not exact(e, ["checkId", "minimum"]):
                return False
            if not is_id(e["checkId"]) or e["minimum"] not in ("pass", "independent-pass"):
                return False
            if e["checkId"] in seen_min:
                return False
            seen_min.add(e["checkId"])
    if not unique_list(p["revokedKeyIds"], is_hash, 4096):
        return False
    if not unique_list(p["revokedSubjectDigests"], is_hash, 4096):
        return False
    if not unique_list(p["revokedEvidenceIds"], is_id, 4096):
        return False
    tk = p["trustedKeys"]
    if type(tk) is not list or len(tk) > 256:
        return False
    seen = set()
    for k in tk:
        if not exact(k, ["id", "role", "publicKey"]):
            return False
        if not is_hash(k["id"]) or k["id"] in seen:
            return False
        seen.add(k["id"])
        if k["role"] not in ("self", "independent", "capture-issuer"):
            return False
        der = parse_public_key(k["publicKey"])
        if der is None or hashlib.sha256(der).hexdigest() != k["id"]:
            return False
    return True


def valid_evidence_payload(e):
    if not exact(e, ["schema", "id", "subjectDigest", "scopeId", "profileDigest", "evaluatorDigest",
                     "runId", "checkId", "artifactDigest", "outcome", "source", "observedAt", "expiresAt"]):
        return False
    if e["schema"] != "kya.evidence/v1":
        return False
    for k in ("id", "scopeId", "runId", "checkId"):
        if not is_id(e[k]):
            return False
    for k in ("subjectDigest", "profileDigest", "evaluatorDigest", "artifactDigest"):
        if not is_hash(e[k]):
            return False
    if e["outcome"] not in ("pass", "fail", "abstain", "error"):
        return False
    if e["source"] not in ("runtime", "fixture", "declaration"):
        return False
    if not (is_ts(e["observedAt"]) and is_ts(e["expiresAt"])):
        return False
    return e["expiresAt"] > e["observedAt"]


def valid_incident_payload(e):
    if not exact(e, ["schema", "id", "subjectDigest", "kind", "severity", "refId", "reportedAt", "detailsDigest"]):
        return False
    if e["schema"] != "kya.incident/v1":
        return False
    if not is_id(e["id"]):
        return False
    if not (is_hash(e["subjectDigest"]) and is_hash(e["detailsDigest"])):
        return False
    if e["kind"] not in ("report", "resolution", "appeal"):
        return False
    if e["severity"] not in ("low", "medium", "high", "critical"):
        return False
    if not is_ts(e["reportedAt"]):
        return False
    if e["kind"] == "report":
        if e["refId"] is not None:
            return False
    else:
        if not is_id(e["refId"]) or e["refId"] == e["id"]:
            return False
    return True


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032), Python integers
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENT = (0, 1, 1, 0)


def _pt_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = t1 * 2 * _D * t2 % _P
    D = z1 * 2 * z2 % _P
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_mul(s, pt):
    q = _IDENT
    while s > 0:
        if s & 1:
            q = _pt_add(q, pt)
        pt = _pt_add(pt, pt)
        s >>= 1
    return q


def _pt_eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _pt_decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = (u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P)) % _P
    vxx = v * x * x % _P
    if vxx == u % _P:
        pass
    elif vxx == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = _pt_decode(_GY.to_bytes(32, "little"))


def small_order(pt):
    q = _pt_mul(8, pt)
    return q[0] % _P == 0 and (q[1] - q[2]) % _P == 0


def key_acceptable(raw32):
    pt = _pt_decode(raw32)
    return pt is not None and not small_order(pt)


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    A = _pt_decode(pub)
    R = _pt_decode(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    lhs = _pt_mul(s, _G)
    rhs = _pt_add(R, _pt_mul(h, A))
    return _pt_eq(lhs, rhs)


# ---------------------------------------------------------------------------
# Public keys and signatures
# ---------------------------------------------------------------------------

_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{59}=")
_PEM_HEAD = "-----BEGIN PUBLIC KEY-----\n"
_PEM_FOOT = "\n-----END PUBLIC KEY-----\n"


def parse_public_key(pem):
    """Return the 44 byte DER SPKI when pem is the one accepted spelling of an acceptable key."""
    if type(pem) is not str or len(pem) > 2000:
        return None
    if not (pem.startswith(_PEM_HEAD) and pem.endswith(_PEM_FOOT)):
        return None
    body = pem[len(_PEM_HEAD):len(pem) - len(_PEM_FOOT)]
    if _B64_RE.fullmatch(body) is None:
        return None
    try:
        der = base64.b64decode(body.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(der).decode("ascii") != body:
        return None
    if len(der) != 44 or der[:12] != _SPKI_PREFIX:
        return None
    if not key_acceptable(der[12:]):
        return None
    return der


_SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")


def decode_signature(sig):
    if type(sig) is not str or _SIG_RE.fullmatch(sig) is None:
        return None
    raw = base64.urlsafe_b64decode(sig + "==")
    if len(raw) != 64:
        return None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != sig:
        return None
    return raw


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def result(op, **members):
    r = {"schema": "kya.impl-result/v1", "operation": op}
    r.update(members)
    return r


def op_canonicalize(inputs):
    if not exact(inputs, ["text"]) or type(inputs["text"]) is not str:
        refuse("bad inputs")
    value = parse_strict(inputs["text"])
    text = canonical(value)
    return result("canonicalize", canonical=text, sha256=sha256_hex(text))


_DIGEST_VALIDATORS = {
    "manifest": valid_manifest,
    "scope": valid_manifest,
    "profile": valid_profile,
    "policy": valid_policy,
    "evidence-signing-input": valid_evidence_payload,
    "incident-signing-input": valid_incident_payload,
}


def op_digest(inputs):
    if not exact(inputs, ["artifact", "value"]) or type(inputs["artifact"]) is not str:
        refuse("bad inputs")
    art = inputs["artifact"]
    if art not in _DIGEST_VALIDATORS:
        refuse("unknown artifact")
    value = inputs["value"]
    if not _DIGEST_VALIDATORS[art](value):
        refuse("value breaks the field rules")
    if art == "scope":
        pre = canonical(value["scope"])
    elif art == "evidence-signing-input":
        pre = "kya.evidence/v1\n" + canonical(value)
    elif art == "incident-signing-input":
        pre = "kya.incident/v1\n" + canonical(value)
    else:
        pre = canonical(value)
    return result("digest", artifact=art, preimage=pre, digest=sha256_hex(pre))


def _invalid(kind, code):
    return result("verify-envelope", kind=kind, valid=False, failure=code, keyId=None,
                  envelopeDigest=None, signingInputSha256=None)


def verify_envelope_core(kind, env):
    """Return (failure code or None, details dict)."""
    if not exact(env, ["payload", "proof"]):
        return "MALFORMED_ENVELOPE", None
    payload = env["payload"]
    ok = valid_evidence_payload(payload) if kind == "evidence" else valid_incident_payload(payload)
    if not ok:
        return "INVALID_PAYLOAD", None
    proof = env["proof"]
    if not exact(proof, ["algorithm", "keyId", "publicKey", "signature"]):
        return "MALFORMED_PROOF", None
    if proof["algorithm"] != "Ed25519":
        return "UNSUPPORTED_ALGORITHM", None
    der = parse_public_key(proof["publicKey"]) if is_hash(proof["keyId"]) else None
    if der is None:
        return "INVALID_KEY", None
    if hashlib.sha256(der).hexdigest() != proof["keyId"]:
        return "KEY_ID_MISMATCH", None
    sig = decode_signature(proof["signature"])
    if sig is None:
        return "INVALID_SIGNATURE_ENCODING", None
    signing = ("kya.evidence/v1\n" if kind == "evidence" else "kya.incident/v1\n") + canonical(payload)
    if not ed25519_verify(der[12:], signing.encode("utf-8"), sig):
        return "SIGNATURE_INVALID", None
    return None, {"keyId": proof["keyId"], "envelopeDigest": sha256_hex(canonical(env)),
                  "signingInputSha256": sha256_hex(signing)}


def op_verify_envelope(inputs):
    if not exact(inputs, ["kind", "envelope"]) or type(inputs["kind"]) is not str:
        refuse("bad inputs")
    kind = inputs["kind"]
    if kind not in ("evidence", "incident"):
        refuse("unknown kind")
    code, det = verify_envelope_core(kind, inputs["envelope"])
    if code is not None:
        return _invalid(kind, code)
    return result("verify-envelope", kind=kind, valid=True, failure=None, keyId=det["keyId"],
                  envelopeDigest=det["envelopeDigest"], signingInputSha256=det["signingInputSha256"])


SUBJECT_CODES = ("SUBJECT_REVOKED", "SUBJECT_EXPIRED", "SUBJECT_NOT_YET_VALID")
BLOCKER_CODES = SUBJECT_CODES + (
    "CRITICAL_CHECK_FAILED", "CRITICAL_CHECK_UNPROVEN", "COVERAGE_BELOW_POLICY",
    "INDEPENDENT_COVERAGE_BELOW_POLICY", "SCORE_BELOW_POLICY", "AMBIGUOUS_RUNS", "RUN_CONFLICT",
    "RUN_INVALIDATED", "MIXED_RUN_ISSUERS", "REPEATED_RUN_CHECKS", "NO_SCORED_OBSERVATIONS",
    "NO_OBSERVED_CHECKS", "PRINCIPAL_UNBOUND", "MANDATORY_MINIMUM_NOT_MET", "MANDATORY_MINIMUM_UNPROVEN",
)
_MODES = ("none", "runtime", "fixture", "mixed")
_DECISIONS = ("qualified", "insufficient-evidence", "blocked", "expired", "revoked")


def _report_digest_ok(r):
    body = dict((k, v) for k, v in r.items() if k != "reportDigest")
    return sha256_hex(canonical(body)) == r["reportDigest"]


def verify_assessment(r):
    """Checksum and blocker code rules; the checks a report needs before anything relies on it."""
    if not is_obj(r) or r.get("schema") != "kya.assessment/v1":
        refuse("not an assessment")
    if not is_hash(r.get("reportDigest")) or not _report_digest_ok(r):
        refuse("report checksum differs")
    if "blockerCodes" in r:
        codes = r["blockerCodes"]
        if type(codes) is not list or type(r.get("blockers")) is not list:
            refuse("blocker codes")
        if len(codes) != len(r["blockers"]):
            refuse("blocker codes")
        for c in codes:
            if type(c) is not str or c not in BLOCKER_CODES:
                refuse("blocker codes")
        if r.get("decision") == "qualified" and codes:
            refuse("blocker codes on a qualified report")
        if not any(c in SUBJECT_CODES for c in codes) and type(r.get("checks")) is list:
            failed = 0
            for c in r["checks"]:
                if is_obj(c) and c.get("critical") is True and c.get("status") == "fail":
                    failed += 1
            if failed != codes.count("CRITICAL_CHECK_FAILED"):
                refuse("critical failure count differs from the codes")


def check_report(r):
    verify_assessment(r)
    for k in ("scopeDigest", "profileDigest", "evaluatorDigest", "policyDigest"):
        if not is_hash(r.get(k)):
            refuse("missing " + k)
    if not is_id(r.get("scopeId")):
        refuse("scopeId")
    if r.get("evidenceMode") not in _MODES or r.get("decision") not in _DECISIONS:
        refuse("mode or decision")
    sc = r.get("score")
    if not is_obj(sc) or type(sc.get("earned")) is not int:
        refuse("score")
    cs = r.get("checks")
    if type(cs) is not list:
        refuse("checks")
    for c in cs:
        if not is_obj(c) or not is_id(c.get("id")) or type(c.get("weight")) is not int or type(c.get("status")) is not str:
            refuse("check entry")


def op_compare(inputs):
    if not exact(inputs, ["left", "right"]):
        refuse("bad inputs")
    a, b = inputs["left"], inputs["right"]
    check_report(a)
    check_report(b)
    reason = None
    if a["scopeId"] != b["scopeId"]:
        reason = "SCOPE_ID_DIFFERS"
    elif a["scopeDigest"] != b["scopeDigest"]:
        reason = "SCOPE_DIGEST_DIFFERS"
    elif a["profileDigest"] != b["profileDigest"]:
        reason = "PROFILE_DIFFERS"
    elif a["evaluatorDigest"] != b["evaluatorDigest"]:
        reason = "EVALUATOR_DIFFERS"
    elif a["policyDigest"] != b["policyDigest"]:
        reason = "POLICY_DIFFERS"
    elif a["evidenceMode"] != b["evidenceMode"]:
        reason = "EVIDENCE_MODE_DIFFERS"
    else:
        ca, cb = a["checks"], b["checks"]
        if len(ca) != len(cb) or any(x["id"] != y["id"] or x["weight"] != y["weight"] for x, y in zip(ca, cb)):
            reason = "CHECK_POPULATION_DIFFERS"
        elif any(x["status"] not in ("pass", "fail") for x in ca + cb):
            reason = "CHECKS_INCOMPLETE"
    if reason is not None:
        return result("compare", comparable=False, reason=reason, left=a["reportDigest"],
                      right=b["reportDigest"], scoreDelta=None, decisionChanged=None, measurement=None)
    return result("compare", comparable=True, reason=None, left=a["reportDigest"], right=b["reportDigest"],
                  scoreDelta=b["score"]["earned"] - a["score"]["earned"],
                  decisionChanged=a["decision"] != b["decision"],
                  measurement="same-policy evidence comparison; not a causal improvement claim")


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def ts_ms(ts):
    y, mo, d, h, mi, s, ms = [int(g) for g in _TS_RE.fullmatch(ts).groups()]
    days = calendar.timegm((y, mo, d, 0, 0, 0))
    return (days + h * 3600 + mi * 60 + s) * 1000 + ms


def ms_ts(ms):
    secs, rem = divmod(int(ms), 1000)
    t = time.gmtime(secs)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour,
                                                    t.tm_min, t.tm_sec, rem)


def round6(num, den):
    """round(num / den * 1e6) / 1e6 in binary64, halves toward positive infinity (Math.round)."""
    if den == 0:
        return 0
    x = num / den * 1000000.0
    r = float(int(x))
    if x - r >= 0.5:
        r += 1.0
    v = r / 1000000.0
    if v == int(v):
        return int(v)
    return v


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------

_CODE_TEXT = {
    "MALFORMED_ENVELOPE": "malformed envelope",
    "INVALID_PAYLOAD": "invalid payload",
    "MALFORMED_PROOF": "malformed proof",
    "UNSUPPORTED_ALGORITHM": "unsupported algorithm",
    "INVALID_KEY": "invalid key",
    "KEY_ID_MISMATCH": "key id mismatch",
    "INVALID_SIGNATURE_ENCODING": "invalid signature encoding",
    "SIGNATURE_INVALID": "signature invalid",
}

LIMITATIONS = [
    "Local policy result; not an authorization grant",
    "Signatures attest bytes and key possession, not truthful execution",
    "No universal predictive validation; public suites can be gamed",
]
FIXTURE_LIMITATION = "Includes synthetic fixture evidence; not a real product benchmark"

_CONSERVATIVE = {"fail": 0, "error": 1, "abstain": 2, "pass": 3}


def _bad_reason(kind, code):
    return "Invalid %s record: %s (%s)" % (kind, _CODE_TEXT[code], code)


def op_assess(inputs):
    if not exact(inputs, ["manifest", "profile", "policy", "evidence", "evaluatorDigest", "now"]):
        refuse("bad inputs")
    manifest, profile, policy = inputs["manifest"], inputs["profile"], inputs["policy"]
    evidence, evaluator, now = inputs["evidence"], inputs["evaluatorDigest"], inputs["now"]
    if not valid_manifest(manifest) or not valid_profile(profile) or not valid_policy(policy):
        refuse("invalid manifest, profile or policy")
    if type(evidence) is not list or len(evidence) > 4096 or not is_hash(evaluator) or not is_ts(now):
        refuse("invalid evidence list, evaluator digest or time")
    subject_digest = sha256_hex(canonical(manifest))
    profile_digest = sha256_hex(canonical(profile))
    policy_digest = sha256_hex(canonical(policy))
    scope_digest = sha256_hex(canonical(manifest["scope"]))
    if policy["profileDigest"] != profile_digest or policy["scopeId"] != manifest["scope"]["id"]:
        refuse("policy does not bind this profile and scope")
    checks_by_id = dict((c["id"], c) for c in profile["checks"])
    for mm in policy.get("mandatoryMinimums", []):
        if mm["checkId"] not in checks_by_id:
            refuse("mandatory minimum names an unknown check")
    anchors = dict((k["id"], k) for k in policy["trustedKeys"])
    now_ms = ts_ms(now)

    subject_state = None
    if subject_digest in policy["revokedSubjectDigests"]:
        subject_state = "revoked"
    elif ts_ms(manifest["expiresAt"]) <= now_ms:
        subject_state = "expired"
    elif ts_ms(manifest["issuedAt"]) > now_ms:
        subject_state = "not-yet"

    recs = []
    for idx, env in enumerate(evidence):
        rec = {"index": idx, "id": None, "reason": None, "bound": False, "env": env}
        recs.append(rec)
        code, det = verify_envelope_core("evidence", env)
        if code is not None:
            rec["reason"] = _bad_reason("evidence", code)
            continue
        p = env["payload"]
        rec["id"] = p["id"]
        rec["p"] = p
        rec["keyId"] = det["keyId"]
        rec["digest"] = det["envelopeDigest"]
        anchor = anchors.get(det["keyId"])
        rec["anchor"] = anchor
        reason = None
        if anchor is None:
            reason = "Signer is not a relying-party trust anchor"
        elif anchor["role"] == "capture-issuer":
            reason = "A capture-issuer key cannot issue scoring evidence"
        elif subject_state == "revoked":
            reason = "Subject is revoked"
        elif subject_state == "expired":
            reason = "Subject is expired"
        elif subject_state == "not-yet":
            reason = "Subject is not yet issued"
        elif p["subjectDigest"] != subject_digest:
            reason = "Exact system digest differs"
        elif p["scopeId"] != manifest["scope"]["id"]:
            reason = "Evidence scope differs"
        elif p["profileDigest"] != profile_digest:
            reason = "Frozen profile differs"
        elif p["evaluatorDigest"] != evaluator:
            reason = "Evaluator digest differs"
        elif p["checkId"] not in checks_by_id:
            reason = "Evidence check is outside frozen profile"
        elif p["source"] == "declaration":
            reason = "A declaration cannot satisfy an observed check"
        elif p["source"] not in policy["allowedSources"]:
            reason = "Evidence source is disallowed"
        elif ts_ms(p["observedAt"]) > now_ms:
            reason = "Observation is in the future"
        elif p["observedAt"] < manifest["issuedAt"]:
            reason = "Observation predates manifest"
        if reason is not None:
            rec["reason"] = reason
            continue
        rec["bound"] = True
        if det["keyId"] in policy["revokedKeyIds"]:
            rec["reason"] = "Signing key is revoked"
        elif p["id"] in policy["revokedEvidenceIds"]:
            rec["reason"] = "Evidence is revoked"
        elif ts_ms(p["expiresAt"]) <= now_ms:
            rec["reason"] = "Evidence is expired"
        elif now_ms - ts_ms(p["observedAt"]) >= policy["maxEvidenceAgeSeconds"] * 1000:
            rec["reason"] = "Evidence exceeds freshness policy"

    bound = [r for r in recs if r["bound"]]
    id_count = {}
    for r in bound:
        id_count[r["id"]] = id_count.get(r["id"], 0) + 1
    runs = {}
    for r in bound:
        runs.setdefault(r["p"]["runId"], []).append(r)
    selected = None
    ambiguous = False
    tied = []
    if runs:
        latest = {}
        for rid, rs in runs.items():
            latest[rid] = max(x["p"]["observedAt"] for x in rs)
        top = max(latest.values())
        tied = [rid for rid in runs if latest[rid] == top]
        ambiguous = len(tied) > 1

        def tie_key(rid):
            failed = any(x["p"]["outcome"] == "fail" and checks_by_id[x["p"]["checkId"]]["critical"]
                         for x in runs[rid])
            return (0 if failed else 1, utf16_key(rid))
        selected = sorted(tied, key=tie_key)[0]

    for r in bound:
        if r["reason"] is not None:
            continue
        if id_count[r["id"]] > 1:
            r["reason"] = "Duplicate evidence ID"
        elif r["p"]["runId"] != selected:
            if r["p"]["runId"] in tied:
                r["reason"] = "Equally recent run excluded; ambiguous runs cannot qualify"
            else:
                r["reason"] = "Older run excluded; checks cannot be mixed across runs"

    sel_bound = runs.get(selected, []) if selected is not None else []
    conflict = any(id_count[r["id"]] > 1 for r in sel_bound)
    invalidated = any(r["reason"] in ("Signing key is revoked", "Evidence is revoked", "Evidence is expired",
                                      "Evidence exceeds freshness policy", "Duplicate evidence ID")
                      for r in sel_bound)
    mixed = len(set(r["keyId"] for r in sel_bound)) > 1
    per_check_bound = {}
    for r in sel_bound:
        per_check_bound[r["p"]["checkId"]] = per_check_bound.get(r["p"]["checkId"], 0) + 1
    repeated = any(n > 1 for n in per_check_bound.values())

    kept = {}
    for r in sel_bound:
        if r["reason"] is not None:
            continue
        cid = r["p"]["checkId"]
        cur = kept.get(cid)
        if cur is None:
            kept[cid] = r
        else:
            a = (_CONSERVATIVE[r["p"]["outcome"]], r["p"]["observedAt"])
            b = (_CONSERVATIVE[cur["p"]["outcome"]], cur["p"]["observedAt"])
            if a < b:
                cur["reason"] = "Superseded observation within selected run"
                kept[cid] = r
            else:
                r["reason"] = "Superseded observation within selected run"
    quarantined_checks = set(r["p"]["checkId"] for r in sel_bound if r["reason"] == "Duplicate evidence ID")

    statuses = {}
    for c in profile["checks"]:
        cid = c["id"]
        r = kept.get(cid)
        if r is None or cid in quarantined_checks:
            statuses[cid] = ("unknown", None, None)
        else:
            role = r["anchor"]["role"]
            statuses[cid] = (r["p"]["outcome"], r["p"]["id"], role if role in ("self", "independent") else None)

    W = sum(c["weight"] for c in profile["checks"])
    P = K = I = 0
    dim = dict((d, [0, 0, 0, 0]) for d in DIMENSIONS)  # W, P, K, count
    for c in profile["checks"]:
        st, _, role = statuses[c["id"]]
        dm = dim[c["dimension"]]
        dm[0] += c["weight"]
        dm[3] += 1
        if st == "pass":
            P += c["weight"]
            dm[1] += c["weight"]
        if st in ("pass", "fail"):
            K += c["weight"]
            dm[2] += c["weight"]
            if role == "independent":
                I += c["weight"]
    earned = 1000 * P // W
    upper = 1000 * (P + W - K) // W

    blockers = []
    codes = []

    def add(code, text):
        codes.append(code)
        blockers.append(text)

    if subject_state == "revoked":
        decision = "revoked"
        add("SUBJECT_REVOKED", "Subject digest is revoked by relying policy")
    elif subject_state == "expired":
        decision = "expired"
        add("SUBJECT_EXPIRED", "Manifest has expired")
    elif subject_state == "not-yet":
        decision = "expired"
        add("SUBJECT_NOT_YET_VALID", "Manifest is not yet valid")
    else:
        decision = None
        crit_failed = [c for c in profile["checks"] if c["critical"] and statuses[c["id"]][0] == "fail"]
        if crit_failed:
            decision = "blocked"
            for c in crit_failed:
                add("CRITICAL_CHECK_FAILED", "Critical check failed: " + c["id"])
        else:
            insufficient = False
            for c in profile["checks"]:
                if c["critical"] and statuses[c["id"]][0] in ("unknown", "abstain", "error"):
                    add("CRITICAL_CHECK_UNPROVEN", "Critical check unproven: " + c["id"])
                    insufficient = True
            if K / W < policy["minCoverage"]:
                add("COVERAGE_BELOW_POLICY", "Evidence coverage below relying policy")
                insufficient = True
            if I / W < policy["minIndependentCoverage"]:
                add("INDEPENDENT_COVERAGE_BELOW_POLICY", "Independent coverage below relying policy")
                insufficient = True
            if ambiguous:
                add("AMBIGUOUS_RUNS", "Ambiguous equally recent runs")
                insufficient = True
            if conflict:
                add("RUN_CONFLICT", "Selected run contains quarantined conflicting evidence IDs")
                insufficient = True
            if invalidated:
                add("RUN_INVALIDATED", "Latest bound run contains invalidated evidence; no fallback qualification")
                insufficient = True
            if mixed:
                add("MIXED_RUN_ISSUERS", "Frozen run has multiple evaluator issuers")
                insufficient = True
            if repeated:
                add("REPEATED_RUN_CHECKS", "Frozen check has repeated observations; retry requires a new whole run")
                insufficient = True
            if policy.get("requirePrincipalBinding") is True and "accountableParty" not in manifest["principal"]:
                add("PRINCIPAL_UNBOUND", "Policy requires a declared accountable party; manifest declares none")
                insufficient = True
            if K == 0:
                add("NO_SCORED_OBSERVATIONS", "No scored observations")
                insufficient = True
            if insufficient:
                decision = "insufficient-evidence"
            elif earned < policy["minScore"]:
                add("SCORE_BELOW_POLICY", "Score below relying policy")
                decision = "blocked"
            else:
                decision = "qualified"
        mm_hit = False
        for mm in policy.get("mandatoryMinimums", []):
            st, _, role = statuses[mm["checkId"]]
            if st == "pass" and (mm["minimum"] == "pass" or role == "independent"):
                continue
            mm_hit = True
            if st in ("pass", "fail"):
                add("MANDATORY_MINIMUM_NOT_MET", "Mandatory minimum not met: %s requires %s; observed %s"
                    % (mm["checkId"], mm["minimum"], st))
            else:
                add("MANDATORY_MINIMUM_UNPROVEN", "Mandatory minimum unproven: %s requires %s; observed %s"
                    % (mm["checkId"], mm["minimum"], st))
        if mm_hit:
            decision = "blocked"
        if not kept and decision == "qualified":
            decision = "insufficient-evidence"
            add("NO_OBSERVED_CHECKS", "No observed checks")

    accepted = [r for r in recs if r["reason"] is None]
    modes = set(r["p"]["source"] for r in accepted)
    if not accepted:
        mode = "none"
    elif modes == set(["runtime"]):
        mode = "runtime"
    elif modes == set(["fixture"]):
        mode = "fixture"
    else:
        mode = "mixed"

    valid_until = ts_ms(manifest["expiresAt"])
    for r in accepted:
        valid_until = min(valid_until, ts_ms(r["p"]["expiresAt"]),
                          ts_ms(r["p"]["observedAt"]) + policy["maxEvidenceAgeSeconds"] * 1000)

    entry_digests = [sha256_hex(canonical(e)) for e in evidence]
    limitations = list(LIMITATIONS)
    if mode in ("fixture", "mixed"):
        limitations.append(FIXTURE_LIMITATION)

    dimensions = []
    for d in DIMENSIONS:
        w, p, k, n = dim[d]
        if n == 0:
            dimensions.append({"id": d, "earned": 0, "possible": 0, "upperBound": 0, "coverage": 0,
                               "weight": 0})
        else:
            dimensions.append({"id": d, "earned": 1000 * p // w, "possible": 1000,
                               "upperBound": 1000 * (p + w - k) // w, "coverage": round6(k, w), "weight": w})
    check_entries = []
    for c in profile["checks"]:
        st, eid, role = statuses[c["id"]]
        kr = kept.get(c["id"])
        check_entries.append({"id": c["id"], "dimension": c["dimension"], "title": c["title"],
                              "weight": c["weight"], "critical": c["critical"], "status": st,
                              "evidenceId": eid, "keyId": (kr["keyId"] if eid is not None else None),
                              "independence": role})
    rejected = [{"index": r["index"], "id": r["id"], "reason": r["reason"]} for r in recs
                if r["reason"] is not None]
    report = {
        "schema": "kya.assessment/v1",
        "assessedAt": now,
        "subjectDigest": subject_digest,
        "scopeDigest": scope_digest,
        "scopeId": manifest["scope"]["id"],
        "agentId": manifest["agent"]["id"],
        "agentName": manifest["agent"]["name"],
        "principalId": manifest["principal"]["id"],
        "profileId": profile["id"],
        "profileDigest": profile_digest,
        "policyDigest": policy_digest,
        "evaluatorDigest": evaluator,
        "evidenceBundleDigest": sha256_hex(canonical(entry_digests)),
        "acceptedEvidenceDigests": sorted(r["digest"] for r in accepted),
        "evidenceMode": mode,
        "selectedRunId": selected,
        "ambiguousRuns": ambiguous,
        "decision": decision,
        "score": {"earned": earned, "possible": 1000, "upperBound": upper},
        "coverage": round6(K, W),
        "independentCoverage": round6(I, W),
        "validUntil": ms_ts(valid_until),
        "dimensions": dimensions,
        "checks": check_entries,
        "blockers": blockers,
        "blockerCodes": codes,
        "rejectedEvidence": rejected,
        "limitations": limitations,
    }
    report_digest = sha256_hex(canonical(report))
    report["reportDigest"] = report_digest
    return result("assess", decision=decision, evidenceMode=mode, ambiguousRuns=ambiguous,
                  selectedRunId=selected, score=report["score"], coverage=report["coverage"],
                  independentCoverage=report["independentCoverage"], blockerCodes=codes,
                  validUntil=report["validUntil"],
                  checks=[{"id": c["id"], "status": c["status"], "evidenceId": c["evidenceId"],
                           "independence": c["independence"]} for c in check_entries],
                  rejectedEvidence=rejected, reportDigest=report_digest)


# ---------------------------------------------------------------------------
# currency
# ---------------------------------------------------------------------------

CURRENCY_LIMITS = [
    "Detects change against supplied manifest, policy and clock only; it does not observe runtime behavior",
    "Report checksum is unauthenticated; recompute from trusted inputs before reliance",
    "Incident records are trusted only through the supplied policy anchors; an omitted incident is undetectable",
    "A passing check is not an authorization grant",
]
_TRIGGER_CODES = {
    "clock-regression": ("CLOCK_REGRESSION", "Check time precedes the assessment time"),
    "subject-changed": ("SUBJECT_CHANGED", "Manifest no longer matches the assessed subject digest"),
    "policy-changed": ("POLICY_CHANGED", "Relying policy differs from the assessed policy"),
    "subject-revoked": ("SUBJECT_REVOKED", "Subject digest is revoked by the supplied policy"),
    "assessment-expired": ("ASSESSMENT_EXPIRED", "Assessment validity interval has ended"),
    "assessment-aged": ("ASSESSMENT_AGED", "Assessment is older than the policy maximum age"),
}


def _ignored_key(e):
    return (utf16_key(e["id"] if e["id"] is not None else ""), utf16_key(e["reason"]))


def process_incidents(incidents, policy, subject, now_ms):
    roles = dict((k["id"], k["role"]) for k in policy["trustedKeys"])
    ignored = []
    eligible = []
    seen = set()
    for env in incidents:
        code, det = verify_envelope_core("incident", env)
        if code is not None:
            ignored.append({"id": None, "reason": "Invalid incident record: " + _CODE_TEXT[code] + " (" + code + ")"})
            continue
        if det["envelopeDigest"] in seen:
            continue
        seen.add(det["envelopeDigest"])
        p = env["payload"]
        key = det["keyId"]
        if key not in roles:
            ignored.append({"id": p["id"], "reason": "Signing key is not a trusted anchor"})
        elif key in policy["revokedKeyIds"]:
            ignored.append({"id": p["id"], "reason": "Signing key is revoked"})
        elif p["subjectDigest"] != subject:
            ignored.append({"id": p["id"], "reason": "Incident concerns a different subject"})
        else:
            rec = dict(p)
            rec["keyId"] = key
            rec["role"] = roles[key]
            rec["future"] = ts_ms(p["reportedAt"]) > now_ms
            eligible.append(rec)
    blocking_sev = ("high", "critical")
    reports = [e for e in eligible if e["kind"] == "report"]
    counts = {}
    for e in reports:
        counts[e["id"]] = counts.get(e["id"], 0) + 1
    for iid in counts:
        if counts[iid] > 1:
            ignored.append({"id": iid, "reason": "Conflicting records share an ID; reports kept open, resolutions cannot target them"})
    groups = {}
    for e in eligible:
        if e["kind"] != "report":
            groups.setdefault((e["keyId"], e["id"]), []).append(e)
    others = []
    for g in groups.values():
        if len(g) > 1:
            for e in g:
                ignored.append({"id": e["id"], "reason": "Conflicting records share one key and ID; not honoured"})
        else:
            others.append(g[0])
    live = []
    for e in reports:
        if e["future"] and e["severity"] not in blocking_sev:
            ignored.append({"id": e["id"], "reason": "Incident is dated in the future"})
        else:
            if e["future"]:
                ignored.append({"id": e["id"], "reason": "Blocking incident is dated in the future (clock skew or misdated); kept open"})
            live.append(e)
    resolved = set()
    appealed = set()
    for e in others:
        if e["future"]:
            ignored.append({"id": e["id"], "reason": "Incident is dated in the future"})
            continue
        targets = [r for r in live if r["id"] == e["refId"]]
        if counts.get(e["refId"], 0) > 1:
            ignored.append({"id": e["id"], "reason": "Ambiguous reference: several reports share this ID"})
        elif not targets:
            ignored.append({"id": e["id"], "reason": "References unknown incident"})
        elif e["kind"] == "appeal":
            appealed.add(targets[0]["id"])
        elif e["role"] != "independent":
            ignored.append({"id": e["id"], "reason": "Resolution requires an independent trusted key"})
        elif targets[0]["keyId"] == e["keyId"]:
            ignored.append({"id": e["id"], "reason": "Reporter cannot resolve its own report"})
        elif ts_ms(e["reportedAt"]) <= ts_ms(targets[0]["reportedAt"]):
            ignored.append({"id": e["id"], "reason": "Resolution must be dated after the incident"})
        else:
            resolved.add((targets[0]["keyId"], targets[0]["id"]))
    blocking = [r for r in live if r["severity"] in blocking_sev]
    open_ids = sorted(set(r["id"] for r in blocking if (r["keyId"], r["id"]) not in resolved), key=utf16_key)
    resolved_ids = sorted(set(r["id"] for r in blocking if (r["keyId"], r["id"]) in resolved)
                          - set(open_ids), key=utf16_key)
    observed = sorted(set(r["id"] for r in live if r["severity"] not in blocking_sev), key=utf16_key)
    ignored.sort(key=_ignored_key)
    return {
        "considered": len(incidents),
        "open": open_ids,
        "resolved": resolved_ids,
        "appealed": sorted(appealed, key=utf16_key),
        "observed": observed,
        "ignored": ignored,
    }


def op_currency(inputs):
    if not exact(inputs, ["assessment", "manifest", "policy", "incidents", "now"]):
        refuse("bad inputs")
    a, manifest, policy = inputs["assessment"], inputs["manifest"], inputs["policy"]
    incidents, now = inputs["incidents"], inputs["now"]
    if not valid_manifest(manifest) or not valid_policy(policy):
        refuse("invalid manifest or policy")
    if type(incidents) is not list or len(incidents) > 1024 or not is_ts(now):
        refuse("invalid incidents or time")
    verify_assessment(a)
    for k in ("subjectDigest", "policyDigest", "scopeDigest"):
        if not is_hash(a.get(k)):
            refuse("assessment lacks " + k)
    if a.get("decision") not in _DECISIONS:
        refuse("unknown assessment decision")
    if not is_ts(a.get("assessedAt")) or not is_ts(a.get("validUntil")):
        refuse("assessment lacks its times")
    if ts_ms(a["validUntil"]) < ts_ms(a["assessedAt"]):
        refuse("assessment validity ends before it was assessed")
    now_ms = ts_ms(now)
    subject = sha256_hex(canonical(manifest))
    fired = []
    if now_ms < ts_ms(a["assessedAt"]):
        fired.append("clock-regression")
    if subject != a["subjectDigest"]:
        fired.append("subject-changed")
    if sha256_hex(canonical(policy)) != a["policyDigest"]:
        fired.append("policy-changed")
    if a["subjectDigest"] in policy["revokedSubjectDigests"]:
        fired.append("subject-revoked")
    if now_ms >= ts_ms(a["validUntil"]):
        fired.append("assessment-expired")
    if "maxAssessmentAgeSeconds" in policy and now_ms - ts_ms(a["assessedAt"]) > policy["maxAssessmentAgeSeconds"] * 1000:
        fired.append("assessment-aged")
    inc = process_incidents(incidents, policy, a["subjectDigest"], now_ms)
    triggers = []
    for tid in fired:
        code, detail = _TRIGGER_CODES[tid]
        triggers.append({"id": tid, "code": code, "detail": detail})
    if inc["open"]:
        triggers.append({"id": "incident-open", "code": "INCIDENT_OPEN",
                         "detail": "%d unresolved high or critical incident record(s) for this subject" % len(inc["open"])})
    current = not triggers
    full = {
        "schema": "kya.currency/v1",
        "assessmentDigest": a["reportDigest"],
        "checkedAt": now,
        "current": current,
        "reliable": current and a["decision"] == "qualified",
        "action": "none" if current else "reassess",
        "triggers": triggers,
        "incidents": inc,
        "authenticated": False,
        "limits": CURRENCY_LIMITS,
    }
    digest = sha256_hex(canonical(full))
    return result("currency", current=current, reliable=full["reliable"], action=full["action"],
                  checkedAt=now, assessmentDigest=a["reportDigest"],
                  triggers=[{"id": t["id"], "code": t["code"]} for t in triggers],
                  incidents=inc, resultDigest=digest)


_OPS = {
    "canonicalize": op_canonicalize,
    "digest": op_digest,
    "verify-envelope": op_verify_envelope,
    "compare": op_compare,
    "assess": op_assess,
    "currency": op_currency,
}


def run(raw):
    if len(raw) > MAX_INPUT_BYTES:
        refuse("input too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        refuse("ill-formed UTF-8")
    doc = parse_strict(text)
    if not exact(doc, ["schema", "operation", "inputs"]) or doc["schema"] != "kya.impl-input/v1":
        refuse("bad envelope")
    op = doc["operation"]
    if type(op) is not str:
        refuse("bad operation")
    if op not in _OPS:
        return {"schema": "kya.impl-result/v1", "operation": op, "unsupported": True}
    return _OPS[op](doc["inputs"])


def main():
    try:
        raw = sys.stdin.buffer.read()
        out = run(raw)
        text = json.dumps(out, ensure_ascii=True, separators=(",", ":"))
        if len(text.encode("ascii")) > MAX_INPUT_BYTES:
            raise Refusal("output too large")
    except Refusal as e:
        sys.stderr.write("refused: %s\n" % e)
        return 1
    except RecursionError:
        sys.stderr.write("refused: too deep\n")
        return 1
    sys.stdout.write(text)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
