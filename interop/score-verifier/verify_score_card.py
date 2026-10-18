#!/usr/bin/env python3
"""Second verifier of kya.score-card/v1 (ADR-0033). Python standard library only.

Run as:  python3 -I interop/score-verifier/verify_score_card.py CARD.json
Contract: reads one card, prints one JSON object {"valid": bool, "problems": [...]}
(plus "score" and "cardDigest" when valid); exit 0 when valid, 1 when invalid, 2 on a usage error.
Only valid, score and cardDigest are normative; problem codes are informative.

Written from the text of docs/adr/0033-kya-score-benchmark-profile.md. The first draft was written
from the summary part of that text alone and disagreed with the JavaScript verifier on 18 of 53
shared vectors; the layout and algorithm section of the ADR was then added and this file was
rewritten to follow it (docs/fixlane10-integration.md keeps the log). It does not import the
JavaScript implementation. It is a second implementation by the same team, not an independent review.
"""
import hashlib
import json
import math
import re
import sys

SCHEMA = "kya.score-card/v1"
LABEL = "KYA-SCR-EXPERIMENTAL"
HARD_FLOOR = {"minItems": 30, "minRepeats": 3, "minHeldOutItems": 10}
NON_CLAIMS = [
    "NOT_PREDICTIVE_VALIDITY", "NOT_CALIBRATED_TO_INCIDENTS", "NO_INTER_ASSESSOR_AGREEMENT",
    "NOT_SAFETY_CERTIFICATION", "NOT_ENDORSED_OR_ADOPTED", "NOT_A_PRODUCT_RANKING",
    "INTERVAL_COVERS_ITEM_SAMPLING_ONLY", "SUBJECT_IDENTITY_AS_DECLARED",
    "OFFLINE_EXECUTION_NOT_VERIFIED", "ITEM_SET_MAY_BE_MEMORIZED",
]
OUTCOMES = ("pass", "fail", "abstain", "error")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MASK = 0xFFFFFFFF


class Bad(Exception):
    pass


def need(cond, problem):
    if not cond:
        raise Bad(problem)


# ---- canonical JSON and digest (ADR-0033, Encoding) ----

def es_number(x):
    """ECMAScript Number::toString for finite doubles and safe integers."""
    if isinstance(x, bool):
        raise Bad("bad-number")
    if isinstance(x, int):
        need(abs(x) <= 2 ** 53 - 1, "bad-number")
        return str(x)
    need(math.isfinite(x), "bad-number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    mantissa, _, exp = repr(abs(x)).partition("e")
    whole, _, frac = mantissa.partition(".")
    raw = whole + frac
    lead = len(raw) - len(raw.lstrip("0"))
    digits = raw.lstrip("0").rstrip("0") or "0"
    n = len(whole) - lead + (int(exp) if exp else 0)  # decimal point position relative to digits
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    return sign + (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def canonical(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (int, float)):
        return es_number(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(i) for i in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k]) for k in sorted(v, key=utf16_key)) + "}"
    raise Bad("bad-json")


def digest(v):
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()


# ---- seeded generator (ADR-0033, Generator) ----

def rotl(x, k):
    return ((x << k) | (x >> (32 - k))) & MASK


def seeded_random(seed):
    h = hashlib.sha256(b"kya.score.seed/v1\n" + seed.encode("utf-8")).digest()
    a, b, c, d = (int.from_bytes(h[i * 4:i * 4 + 4], "big") for i in range(4))

    def step():
        nonlocal a, b, c, d
        t = (a + b) & MASK
        a = b ^ (b >> 9)
        b = (c + (c << 3)) & MASK
        c = rotl(c, 21)
        d = (d + 1) & MASK
        t = (t + d) & MASK
        c = (c + t) & MASK
        return t

    for _ in range(12):
        step()

    def below(bound):
        limit = (2 ** 32 // bound) * bound
        while True:
            x = step()
            if x < limit:
                return x % bound

    return below


def js_round(x, places):
    """Math.round(x * 10^places) / 10^places, halves toward positive infinity."""
    scale = 10.0 ** places
    y = x * scale
    f = math.floor(y)
    return (f + 1 if y - f >= 0.5 else f) / scale


def utf16_len(s):
    return len(utf16_key(s)) // 2


# ---- input validation (ADR-0033, Manifest, Floor, Runs) ----

def is_obj(v, keys):
    return isinstance(v, dict) and set(v) == set(keys)


def ident(v):
    need(isinstance(v, str) and ID.match(v) is not None, "bad-identifier")


def hex64(v):
    need(isinstance(v, str) and HEX64.match(v) is not None, "bad-digest")


def check_manifest(m):
    need(is_obj(m, ["subject", "suite", "evaluatorDigest", "judge", "holdoutCommitment", "environment", "bootstrap"]), "manifest-shape")
    for k in ("subject", "suite"):
        need(is_obj(m[k], ["id", "version", "digest"]), "manifest-shape")
        ident(m[k]["id"])
        ident(m[k]["version"])
        hex64(m[k]["digest"])
    hex64(m["evaluatorDigest"])
    if m["judge"] is not None:
        need(is_obj(m["judge"], ["id", "digest"]), "manifest-judge")
        ident(m["judge"]["id"])
        hex64(m["judge"]["digest"])
    if m["holdoutCommitment"] is not None:
        hex64(m["holdoutCommitment"])
    e = m["environment"]
    need(is_obj(e, ["runtime", "offlineDeclared"]) and isinstance(e["runtime"], str) and 1 <= utf16_len(e["runtime"]) <= 128 and isinstance(e["offlineDeclared"], bool), "manifest-environment")
    b = m["bootstrap"]
    need(is_obj(b, ["seed", "resamples"]) and isinstance(b["seed"], str) and 1 <= utf16_len(b["seed"]) <= 128, "manifest-bootstrap")
    need(type(b["resamples"]) is int and 100 <= b["resamples"] <= 20000, "manifest-bootstrap")


def num_ok(v, hi):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and 0 <= v <= hi


def normalise_runs(runs):
    need(isinstance(runs, list) and 1 <= len(runs) <= 32, "runs-shape")
    seen_runs, population, flags, out = set(), None, None, []
    required = {"id", "outcome", "heldOut", "durationMs", "costUsd"}
    for run in runs:
        need(isinstance(run, dict) and set(run) == {"runId", "items"}, "run-shape")
        ident(run["runId"])
        need(run["runId"] not in seen_runs, "duplicate-run")
        seen_runs.add(run["runId"])
        need(isinstance(run["items"], list) and 1 <= len(run["items"]) <= 2000, "item-list")
        seen, items = set(), []
        for it in run["items"]:
            need(isinstance(it, dict) and required <= set(it) <= required | {"canaryExposed"}, "item-shape")
            ident(it["id"])
            need(it["id"] not in seen, "duplicate-item")
            seen.add(it["id"])
            need(it["outcome"] in OUTCOMES and isinstance(it["heldOut"], bool), "item-shape")
            need("canaryExposed" not in it or isinstance(it["canaryExposed"], bool), "item-shape")
            need(num_ok(it["durationMs"], 1e9), "item-duration")
            need(it["costUsd"] is None or num_ok(it["costUsd"], 1e6), "item-cost")
            items.append({"id": it["id"], "outcome": it["outcome"], "heldOut": it["heldOut"], "durationMs": it["durationMs"], "costUsd": it["costUsd"], "canaryExposed": it.get("canaryExposed") is True})
        items.sort(key=lambda x: utf16_key(x["id"]))
        pop, fl = [x["id"] for x in items], [x["heldOut"] for x in items]
        if population is None:
            population, flags = pop, fl
        else:
            need(pop == population, "population-differs")
            need(fl == flags, "held-out-flag-differs")
        out.append({"runId": run["runId"], "items": items})
    return out


# ---- recomputation (ADR-0033, Aggregates and Other results) ----

def aggregate(passes, repeats, seed, label, resamples):
    m = len(passes)
    denom = m * repeats
    below = seeded_random(seed + "|" + label)
    sums = []
    for _ in range(resamples):
        s = 0
        for _ in range(m):
            s += passes[below(m)]
        sums.append(s)
    sums.sort()
    k = resamples * 25 // 1000
    return {
        "items": m, "repeats": repeats, "score": 1000 * sum(passes) // denom,
        "ci95": {"low": 1000 * sums[k] // denom, "high": 1000 * sums[resamples - 1 - k] // denom},
        "resamples": resamples,
    }


def recompute_results(manifest, runs):
    r = len(runs)
    items0 = runs[0]["items"]
    n = len(items0)
    passes = [sum(1 for run in runs if run["items"][i]["outcome"] == "pass") for i in range(n)]
    seed, b = manifest["bootstrap"]["seed"], manifest["bootstrap"]["resamples"]
    held = [passes[i] for i in range(n) if items0[i]["heldOut"]]
    pub = [passes[i] for i in range(n) if not items0[i]["heldOut"]]
    headline = aggregate(passes, r, seed, "all", b)
    held_agg = aggregate(held, r, seed, "heldout", b)
    pub_agg = aggregate(pub, r, seed, "public", b) if pub else None
    counts = {o: 0 for o in OUTCOMES}
    micro, known, dur_sum, max_item, canary = 0, 0, 0.0, 0, 0
    for run in runs:
        for it in run["items"]:
            counts[it["outcome"]] += 1
            canary += 1 if it["canaryExposed"] else 0
            dur_sum += it["durationMs"]
            max_item = max(max_item, it["durationMs"])
            if it["costUsd"] is not None:
                known += 1
                y = it["costUsd"] * 1e6
                f = math.floor(y)
                micro += f + 1 if y - f >= 0.5 else f
    counts["denominator"] = n * r
    per_run = [1000 * sum(1 for it in run["items"] if it["outcome"] == "pass") // n for run in runs]
    mu = sum(per_run) / r
    sd = math.sqrt(sum((x - mu) * (x - mu) for x in per_run) / (r - 1))
    unstable = sum(1 for i in range(n) if len({run["items"][i]["outcome"] for run in runs}) > 1)
    return {
        "headline": headline, "heldOut": held_agg, "public": pub_agg,
        "publicMinusHeldOut": None if pub_agg is None else pub_agg["score"] - held_agg["score"],
        "outcomes": counts,
        "repeatVariance": {"perRunScores": per_run, "mean": js_round(mu, 6), "sd": js_round(sd, 6), "min": min(per_run), "max": max(per_run), "unstableItemShare": js_round(unstable / n, 6)},
        "cost": {"totalUsd": micro / 1e6 if known == n * r else None, "knownItems": known, "items": n * r},
        "runtime": {"totalDurationMs": js_round(dur_sum, 3), "meanPerRunDurationMs": js_round(dur_sum / r, 3), "maxItemDurationMs": max_item},
        "integrity": {"canaryExposures": canary},
    }


def verify(card):
    problems = []
    try:
        need(isinstance(card, dict) and card.get("schema") == SCHEMA, "wrong-schema")
        need(set(card) == {"schema", "label", "manifest", "floor", "runs", "runDigest", "results", "nonClaims", "cardDigest"}, "unexpected-or-missing-fields")
        body = {k: v for k, v in card.items() if k != "cardDigest"}
        if digest(body) != card["cardDigest"]:
            problems.append("card-digest-differs")
        if digest(card["runs"]) != card["runDigest"]:
            problems.append("run-digest-differs")
        floor = card["floor"]
        floor_ok = is_obj(floor, list(HARD_FLOOR)) and all(type(floor[k]) is int and floor[k] >= v for k, v in HARD_FLOOR.items())
        if not floor_ok:
            problems.append("floor-below-hard-minimum")
        use_floor = floor if floor_ok else dict(HARD_FLOOR)
        check_manifest(card["manifest"])
        runs = normalise_runs(card["runs"])
        held = sum(1 for it in runs[0]["items"] if it["heldOut"])
        if len(runs[0]["items"]) < use_floor["minItems"] or len(runs) < use_floor["minRepeats"] or held < use_floor["minHeldOutItems"] or card["manifest"]["holdoutCommitment"] is None:
            raise Bad("evidence-floor-not-met")
        rebuilt_body = {
            "schema": SCHEMA, "label": LABEL, "manifest": card["manifest"], "floor": use_floor, "runs": runs,
            "runDigest": digest(runs), "results": recompute_results(card["manifest"], runs), "nonClaims": list(NON_CLAIMS),
        }
        rebuilt = dict(rebuilt_body, cardDigest=digest(rebuilt_body))
        if canonical(rebuilt["results"]) != canonical(card["results"]):
            problems.append("results-differ-from-recomputation")
        if canonical(rebuilt) != canonical(card):
            problems.append("card-differs-from-recomputation")
    except Bad as error:
        problems.append(str(error))
    except (KeyError, TypeError, ValueError, ZeroDivisionError, IndexError, StopIteration, OverflowError):
        problems.append("unverifiable")
    if problems:
        return {"valid": False, "problems": sorted(set(problems))}
    return {"valid": True, "problems": [], "score": card["results"]["headline"]["score"], "cardDigest": card["cardDigest"]}


def strict_load(text):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError("duplicate member")
            d[k] = v
        return d

    def no_const(name):
        raise ValueError("non finite number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=no_const)


def main(argv):
    if len(argv) != 2:
        print("usage: verify_score_card.py CARD.json", file=sys.stderr)
        return 2
    try:
        with open(argv[1], "r", encoding="utf-8") as handle:
            card = strict_load(handle.read())
    except (OSError, ValueError) as error:
        print(json.dumps({"valid": False, "problems": ["unreadable-json"]}))
        print(str(error), file=sys.stderr)
        return 1
    result = verify(card)
    print(json.dumps(result))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
