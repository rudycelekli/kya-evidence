"""Project-authored Python implementation of the three Passport conformance operations."""
import hashlib
import json
from pathlib import Path
import re
import sys
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from kya_portability import canonical_public_pem, digest, identifier, parse_json, proof_bytes, read_bounded, require, timestamp


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "Unexpected fields")


def hex_digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "Invalid digest")
    return value


def key_id(pem):
    return hashlib.sha256(canonical_public_pem(pem)).hexdigest()


def signature(payload, encoded, pem, domain):
    envelope = {"payload": payload, "proof": {"algorithm": "Ed25519", "publicKey": pem,
                                                "keyId": key_id(pem), "signature": encoded}}
    require(proof_bytes(envelope, domain, True)["verified"], "Signature not verified")


def passport_history(inputs):
    records, registry = inputs["history"], inputs["registry"]
    require(type(records) is list and 0 < len(records) <= 128, "Invalid history")
    initial = records[0]["event"]
    active = None
    previous = None
    agent_keys, controller_keys = [], []
    for position, record in enumerate(records):
        event = record["event"]
        v2 = event["schema"] == "kya.passport-event/v2"
        fields(record, "event controllerSignature agentSignature" + (" recoverySignature" if v2 else ""))
        fields(event, "schema operation registry passportId previous agentId principalId controllerPublicKey agentPublicKey manifestDigest"
               + (" recoveryPublicKey" if v2 else ""))
        require(event["schema"] in ("kya.passport-event/v1", "kya.passport-event/v2"), "Invalid event schema")
        operation = event["operation"]
        require(operation in ("register", "rotate", "revise", "revoke") or v2 and operation == "recover", "Invalid operation")
        require(event["registry"] == registry and isinstance(registry, str) and 0 < len(registry) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in registry), "Invalid registry")
        require(event["previous"] == previous, "Wrong predecessor")
        for name in ("passportId", "manifestDigest"):
            hex_digest(event[name])
        for name in ("agentId", "principalId"):
            identifier(event[name], name)
        controller = key_id(event["controllerPublicKey"])
        if position == 0:
            require(operation == "register", "Missing registration")
            identity = {name: event[name] for name in ("registry", "agentId", "principalId")}
            identity.update(schema="kya.passport-id/v2" if v2 else "kya.passport-id/v1", controllerKeyId=controller)
            if v2:
                identity["recoveryKeyId"] = key_id(event["recoveryPublicKey"])
            require(event["passportId"] == digest(identity), "Wrong Passport ID")
            controller_keys.append(controller)
        else:
            require(active is not None and operation != "register", "Invalid lifecycle")
            require(all(event.get(name) == initial.get(name)
                        for name in ("schema", "passportId", "agentId", "principalId", "recoveryPublicKey")), "Identity changed")
            if operation == "recover":
                require(controller not in controller_keys and controller not in agent_keys, "Reused controller key")
                controller_keys.append(controller)
            else:
                require(controller == controller_keys[-1], "Retired controller")
        signature(event, record["controllerSignature"], event["controllerPublicKey"], event["schema"])
        if v2:
            recovery_key = key_id(event["recoveryPublicKey"])
            require(recovery_key != controller, "Shared recovery key")
            if operation in ("register", "recover"):
                signature(event, record["recoverySignature"], event["recoveryPublicKey"], event["schema"])
            else:
                require(record["recoverySignature"] is None, "Unexpected recovery signature")
        if operation == "revoke":
            require(event["agentPublicKey"] is None and record["agentSignature"] is None
                    and event["manifestDigest"] == active["manifestDigest"], "Invalid revocation")
            active = None
        else:
            agent = key_id(event["agentPublicKey"])
            require(agent not in controller_keys and (not v2 or agent != recovery_key), "Shared agent key")
            signature(event, record["agentSignature"], event["agentPublicKey"], event["schema"])
            if operation == "revise":
                require(agent == active["fingerprint"] and event["manifestDigest"] != active["manifestDigest"], "Invalid revision")
            else:
                require(agent not in agent_keys, "Reused agent key")
                agent_keys.append(agent)
            active = {"fingerprint": agent, "manifestDigest": event["manifestDigest"]}
        previous = digest(record)
    require(len(records) < 128 or active is None, "Final slot reserved")
    result = {name: initial[name] for name in ("passportId", "agentId", "principalId")}
    result.update(head=previous, status="revoked" if active is None else "active", current=active, fingerprints=agent_keys)
    if initial["schema"] == "kya.passport-event/v2":
        result.update(controllerFingerprint=controller_keys[-1], recoveryEnabled=True)
    return result


def membership(member, root, count):
    fields(member, "index leaf siblings")
    position, leaf, siblings = member["index"], member["leaf"], member["siblings"]
    require(type(position) is int and 0 <= position < count and type(siblings) is list, "Invalid position")
    fields(leaf, "key value")
    require(re.fullmatch(r"(passport|fingerprint):[a-f0-9]{64}", leaf["key"]) is not None, "Invalid leaf key")
    current = digest(["kya.registry-leaf/v1", leaf])
    width, consumed = count, 0
    while width > 1:
        sibling = hex_digest(siblings[consumed])
        if (position ^ 1) >= width:
            require(sibling == current, "Invalid duplication")
        left, right = (sibling, current) if position % 2 else (current, sibling)
        current = digest(["kya.registry-node/v1", left, right])
        width, position, consumed = (width + 1) // 2, position // 2, consumed + 1
    require(current == root and consumed == len(siblings), "Wrong proof root")
    return leaf


def lookup_value(query, proof, root, count):
    fields(query, "kind digest")
    require(query["kind"] in ("passport", "fingerprint"), "Invalid kind")
    key = query["kind"] + ":" + hex_digest(query["digest"])
    if "member" in proof:
        fields(proof, "member")
        leaf = membership(proof["member"], root, count)
        require(leaf["key"] == key, "Wrong proof key")
        return leaf["value"]
    fields(proof, "left right")
    left, right = proof["left"], proof["right"]
    if count == 0:
        require(left is right is None and root == digest(["kya.registry-empty/v1"]), "Invalid empty proof")
    else:
        if left is not None:
            require(membership(left, root, count)["key"] < key, "Invalid left boundary")
        if right is not None:
            require(membership(right, root, count)["key"] > key, "Invalid right boundary")
        require((left["index"] if left is not None else -1) + 1 ==
                (right["index"] if right is not None else count), "Nonadjacent absence")
    return None


def witnessed_lookup(inputs):
    signed, trust, endorsements = (inputs[name] for name in ("signed", "trust", "endorsements"))
    fields(signed, "checkpoint signature")
    cp = signed["checkpoint"]
    fields(cp, "schema registry epoch previous root count issuedAt expiresAt")
    domain = "kya.registry-checkpoint/v1"
    require(cp["schema"] == domain and cp["registry"] == trust["registry"], "Wrong registry")
    epoch, count = cp["epoch"], cp["count"]
    require(type(epoch) is int and epoch >= 1 and type(count) is int and 0 <= count <= 1_000_000, "Invalid epoch or count")
    if epoch == 1:
        require(cp["previous"] is None, "Unexpected predecessor")
    else:
        hex_digest(cp["previous"])
    root = hex_digest(cp["root"])
    for value in (inputs["now"], cp["issuedAt"], cp["expiresAt"]):
        timestamp(value, "checkpoint time")
    require(cp["issuedAt"] <= inputs["now"] < cp["expiresAt"], "Expired or future checkpoint")
    require((datetime.fromisoformat(cp["expiresAt"][:-1]) - datetime.fromisoformat(cp["issuedAt"][:-1])).total_seconds() <= 300,
            "Checkpoint lifetime")
    signature(cp, signed["signature"], trust["originPublicKey"], domain)
    cp_digest = digest(cp)
    if "checkpointPin" in trust:
        pin = trust["checkpointPin"]
        fields(pin, "epoch checkpointDigest")
        hex_digest(pin["checkpointDigest"])
        require(type(pin["epoch"]) is int and pin["epoch"] >= 1 and
                (epoch > pin["epoch"] or (epoch == pin["epoch"] and cp_digest == pin["checkpointDigest"])), "Rollback")
    minimum = trust.get("minimumEpoch", 1)
    require(type(minimum) is int and 1 <= minimum <= epoch, "Roster handoff")
    witnesses = trust["witnessPublicKeys"]
    require(type(witnesses) is list and 2 <= len(witnesses) <= 16 and len(witnesses) == len(endorsements), "Incomplete witness set")
    remaining = {key_id(pem): pem for pem in witnesses}
    require(len(remaining) == len(witnesses) and key_id(trust["originPublicKey"]) not in remaining, "Shared keys")
    for endorsement in endorsements:
        fields(endorsement, "witnessId checkpointDigest signature")
        require(endorsement["checkpointDigest"] == cp_digest, "Different checkpoint")
        signature(cp, endorsement["signature"], remaining.pop(endorsement["witnessId"]), "kya.registry-witness/v1")
    return {"checkpointDigest": cp_digest, "epoch": epoch,
            "value": lookup_value(inputs["query"], inputs["proof"], root, count)}


def downstream_receipt(inputs):
    envelope, delivery, pem = (inputs[name] for name in ("envelope", "delivery", "publicKey"))
    fields(envelope, "receipt signature")
    receipt = envelope["receipt"]
    fields(receipt, "schema operationId requestDigest routeRevision outcome")
    domain = "kya.mcp-receipt/v1"
    require(receipt["schema"] == domain and receipt["outcome"] in ("confirmed-applied", "confirmed-not-applied"), "Invalid receipt")
    for key in ("operationId", "requestDigest", "routeRevision"):
        require(receipt[key] == hex_digest(delivery[key]), "Wrong delivery binding")
    signature(receipt, envelope["signature"], pem, domain)
    return {"operationId": receipt["operationId"], "outcome": receipt["outcome"], "receiptDigest": digest(envelope)}


def main():
    # A missing backend is infrastructure failure, never evidence of valid rejections.
    import cryptography  # noqa: F401
    request = parse_json(read_bounded())
    fields(request, "schema operation inputs")
    require(request["schema"] == "kya.passport-conformance-input/v1", "Wrong input schema")
    operation = request["operation"]
    operations = {"passport-history": passport_history, "witnessed-lookup": witnessed_lookup, "downstream-receipt": downstream_receipt}
    response = {"schema": "kya.passport-conformance-result/v1", "operation": operation, "status": "unsupported"}
    if operation in operations:
        try:
            response.update(status="accept", value=operations[operation](request["inputs"]))
        except (ValueError, TypeError, KeyError, IndexError):
            response["status"] = "reject"
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    main()
