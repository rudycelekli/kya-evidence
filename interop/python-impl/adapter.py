#!/usr/bin/env python3
"""KYA contract version 2, Python 3 implementation of four operations.

Standard library only. Written from docs/SPECIFICATION.md, docs/IMPLEMENTERS-GUIDE.md,
interop/impl-contract/README.md and ADR-0034. Operations implemented: canonicalize,
digest, verify-envelope, compare. Every other operation answers unsupported.

Ed25519 verification is implemented here from RFC 8032 with Python integers; it is not
constant time and must not be used to sign or to verify secrets.
"""
import sys
import re
import json
import hashlib
import base64
import binascii

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


def op_verify_envelope(inputs):
    if not exact(inputs, ["kind", "envelope"]) or type(inputs["kind"]) is not str:
        refuse("bad inputs")
    kind = inputs["kind"]
    if kind not in ("evidence", "incident"):
        refuse("unknown kind")
    env = inputs["envelope"]
    if not exact(env, ["payload", "proof"]):
        return _invalid(kind, "MALFORMED_ENVELOPE")
    payload = env["payload"]
    ok = valid_evidence_payload(payload) if kind == "evidence" else valid_incident_payload(payload)
    if not ok:
        return _invalid(kind, "INVALID_PAYLOAD")
    proof = env["proof"]
    if not exact(proof, ["algorithm", "keyId", "publicKey", "signature"]):
        return _invalid(kind, "MALFORMED_PROOF")
    if proof["algorithm"] != "Ed25519":
        return _invalid(kind, "UNSUPPORTED_ALGORITHM")
    der = parse_public_key(proof["publicKey"]) if is_hash(proof["keyId"]) else None
    if der is None:
        return _invalid(kind, "INVALID_KEY")
    if hashlib.sha256(der).hexdigest() != proof["keyId"]:
        return _invalid(kind, "KEY_ID_MISMATCH")
    sig = decode_signature(proof["signature"])
    if sig is None:
        return _invalid(kind, "INVALID_SIGNATURE_ENCODING")
    signing = ("kya.evidence/v1\n" if kind == "evidence" else "kya.incident/v1\n") + canonical(payload)
    if not ed25519_verify(der[12:], signing.encode("utf-8"), sig):
        return _invalid(kind, "SIGNATURE_INVALID")
    return result("verify-envelope", kind=kind, valid=True, failure=None, keyId=proof["keyId"],
                  envelopeDigest=sha256_hex(canonical(env)), signingInputSha256=sha256_hex(signing))


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


def check_report(r):
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


_OPS = {
    "canonicalize": op_canonicalize,
    "digest": op_digest,
    "verify-envelope": op_verify_envelope,
    "compare": op_compare,
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
