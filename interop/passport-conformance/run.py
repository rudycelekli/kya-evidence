#!/usr/bin/env python3
"""Run a candidate against frozen KYA Passport vectors using only Python's standard library."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_OUTPUT = 1_048_576
INPUT = "kya.passport-conformance-input/v1"
OUTPUT = "kya.passport-conformance-result/v1"


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"invalid number {value}")


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def equivalent(actual, expected):
    return json.dumps(actual, sort_keys=True, ensure_ascii=True, allow_nan=False) == json.dumps(
        expected, sort_keys=True, ensure_ascii=True, allow_nan=False
    )


def run_case(vector, command):
    operation = vector["operation"]
    data = json.dumps({"schema": INPUT, "operation": operation, "inputs": vector["inputs"]},
                      separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    with tempfile.TemporaryFile() as stdout:
        try:
            completed = subprocess.run(command, input=data, stdout=stdout, stderr=subprocess.DEVNULL,
                                       timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return "fail", "could not start or timed out"
        if completed.returncode != 0:
            return "fail", "nonzero exit"
        stdout.seek(0)
        raw = stdout.read(MAX_OUTPUT + 1)
    if len(raw) > MAX_OUTPUT or raw.startswith(b"\xef\xbb\xbf"):
        return "fail", "oversized or malformed output"
    try:
        result = decode(raw)
        prefix = {"schema": OUTPUT, "operation": operation}
        if equivalent(result, {**prefix, "status": "unsupported"}):
            return "unsupported", ""
        expected = {**prefix, **vector["expected"]}
        if equivalent(result, expected):
            return "pass", ""
    except (ValueError, UnicodeError, RecursionError):
        return "fail", "invalid JSON result"
    return "fail", "result differs from frozen expectation"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, default=Path(__file__).with_name("vectors.json"))
    parser.add_argument("--out", type=Path, help="write report in addition to stdout")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- executable and its arguments")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply a candidate command after --")
    raw = args.vectors.read_bytes()
    corpus = decode(raw)
    vectors = corpus["vectors"]
    if corpus["schema"] != "kya.passport-vectors/v1" or not vectors or len({v["id"] for v in vectors}) != len(vectors):
        parser.error("invalid fixture corpus")
    results = []
    for vector in vectors:
        status, detail = run_case(vector, command)
        results.append({"id": vector["id"], "operation": vector["operation"], "status": status, "detail": detail})
    totals = {status: sum(r["status"] == status for r in results) for status in ("pass", "fail", "unsupported")}
    report = json.dumps({"schema": "kya.passport-conformance-report/v1", "vectorsSha256": hashlib.sha256(raw).hexdigest(),
                         "totals": totals, "results": results}, indent=2) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 1 if totals["fail"] or totals["unsupported"] else 0


if __name__ == "__main__":
    sys.exit(main())
