# Private pilot kit for a first relying party

This is a protocol for a small, private, offline trial of KYA Evidence by one relying party. It exists so that when the owner finds a willing organisation, the protocol, the commands, the stop rules and the log template are already written.

**No pilot has happened.** No organisation has used KYA Evidence for a real decision. This kit has been read and command-checked by the project team only. No outside party has endorsed it, and it names no pilot partner because none exists. Nothing in it is an outreach message and nothing in it authorizes the project to contact anyone.

## 1. What the pilot is for, and what it is not for

The pilot tests the relying-party process: whether a person who is not on the project team can take the shipped command line tools, write down what a real agent configuration claims to be, set a trust policy, produce an assessment, check later whether that assessment is still current, record an incident, and read every result with the right amount of doubt.

It is not a test of any agent. The shipped command line has no command that runs a real agent through the 18 frozen checks (section 5, "Why the agent results will be thin"). Do not run the pilot to find out whether an agent is safe, and do not let anyone report it as having found that out.

## 2. Parties and roles

| Role | Who | Does |
| :--- | :--- | :--- |
| Pilot owner | A named person at the relying party who has authority over the agents and the data in scope | Decides whether to start, whether to stop, what is recorded and what leaves the workspace. Holds the only approval that matters for publication (section 11). |
| Pilot operator | The pilot owner or someone they appoint | Runs the commands on their own machine and fills in the result log. |
| Project owner | The owner of this repository | Supplies this kit and answers questions. Receives only what the pilot owner approves in writing. Does not receive credentials, keys, traces or agent output. |

The project does not operate any agent for the pilot, does not receive access to any subscription or account and does not run anything on the pilot owner's machine. No contact is published and no monitored channel exists; the only interim route is the one written in [SECURITY.md](../../SECURITY.md). How pilot questions reach the project is for the project owner and pilot owner to agree in writing before the pilot starts.

## 3. Preconditions (all must be true before phase 0)

1. The pilot owner has read sections 1, 5, 9 and 11 and has said, in writing to the project owner, that they accept them.
2. Two or three agents are in scope. Each runs under the pilot owner's own subscription or account, on the pilot owner's own machine, and the terms of that subscription allow this use. The project has no view on those terms; the pilot owner checks them.
3. The machine has Node.js 22 or later and a clone of this repository at a commit the project owner names. No network is needed after the clone. The operator confirms with `node --version`.
4. A pilot workspace directory exists outside the clone, on local disk, readable only by the operator (for example mode 0700). This kit calls it the workspace and uses the shell variable `WORK`.
5. A stop contact exists on the relying party's side: a person who can say stop. Name them in the result log.
6. No production credentials, personal data or customer data are in the workspace or in any manifest.

## 4. Safety envelope

- **Offline.** None of the commands below needs a network. Do not add one. If a command asks for a login, a token or a download, stop (section 8).
- **No data leaves.** Nothing is uploaded, emailed, posted or committed. The workspace is not a git repository and is not in a synced folder.
- **Own subscriptions only.** The project never sees or holds a credential. No command in this kit calls a model provider.
- **Local effects only.** The commands read and write files in the workspace. `kya probe` is the one command that starts other programs: it looks for known agent command line tools and asks each for its version (`--version`). Run it only if the pilot owner is content for those version commands to run, and note that a version string is a declaration, not a capability.
- **Throwaway keys.** Keys generated for the pilot are for the pilot. They are never reused for any other purpose, never copied out of the workspace and deleted at the end.
- **No agent is asked to do anything** in phases 0 to 5.

## 5. Why the agent results will be thin, stated up front

- The demo and benchmark commands use synthetic fixtures. A perfect fixture score says nothing about any real agent.
- A manifest is a declaration written by the operator. It is not observed and not verified.
- Policy templates accept only `runtime` evidence. Without any, an assessment of a real agent comes back as `insufficient-evidence` or `blocked`. That is the correct, honest result.
- The reference capture cell (`scripts/kya-capture.mjs`) runs scripted, simulated agents in a simulated world. It shows how a capture is built and verified, not how a real agent behaves.
- The score card needs at least 30 items, 3 repeats and 10 held-out items, plus a holdout commitment digest, and the operator must supply per-item results from their own harness. Refusal is a likely and informative result.
- A library route exists for wiring one reviewed command wrapper per agent through the bounded command adapter (see [ADAPTERS.md](../ADAPTERS.md)). It is engineering work for the pilot owner, it is optional, and this kit does not assume it. Native vendor adapters are declaration source and cannot satisfy scored checks.

## 6. Protocol

Run from the clone. `WORK` is the workspace. Every `--out` target must not exist yet, so use a new directory each time. The commands take the clock explicitly (`--now`) so results are repeatable. `kya init` stamps the starter manifest with the real current time and an expiry about one day later, and a `--now` earlier than the manifest's `issuedAt` reads as not yet valid. So set `NOW` after phase 1 to the real current time in ISO form, and keep that value for the rest of the day.

```sh
export WORK=$HOME/kya-pilot
mkdir -p "$WORK"
```

After phase 1, with the real time substituted:

```sh
export NOW=2026-01-01T00:00:00.000Z
```

### Phase 0: rehearsal on synthetic fixtures

Goal: learn the commands before any real agent is described. Nothing here concerns a real agent.

```sh
node bin/kya.mjs demo --out "$WORK/rehearsal"
node scripts/kya-check.mjs --help
```


The demo prints a qualified decision with `"fixtureOnly": true`. Expected exit code 0. The demo stamps its manifest with the current clock. Then follow [QUICKSTART-RELYING-PARTY.md](../QUICKSTART-RELYING-PARTY.md) steps 2 to 7 (keys, policies, assessment, currency, incident, accountable party). Record every deviation from the quickstart in the log (section 10).

### Phase 1: describe each agent

For each agent (call them agent-a, agent-b and optionally agent-c):

```sh
node bin/kya.mjs init "$WORK/agent-a"
```

This writes `manifest.json`, `profile.json`, `policy.json` and an empty `evidence.json`, and prints the evaluator digest and `"status":"unmeasured"`. Edit `manifest.json` by hand so it states what the agent actually is: harness, model, tool list and permissions, scope, forbidden actions, approval-required actions, issue and expiry times. Use a pseudonymous principal identifier, not a person's name or email. Do not paste prompts, secrets or customer data.

Then, optionally:

```sh
node bin/kya.mjs inspect "$WORK/agent-a"
node bin/kya.mjs probe
```

`inspect` reads a configuration directory and prints an inventory. Read its output before sharing it with anyone, and record what it reported and whether it was correct. `probe` is described in section 4.

### Phase 2: set the trust policy

Generate two keys: one for the relying party's own monitor (role `self`) and one for a reviewer who is a different person (role `independent`).

```sh
node bin/kya.mjs keygen "$WORK/keys/monitor"
node bin/kya.mjs keygen "$WORK/keys/reviewer"
node scripts/kya-policy-init.mjs --template read-only-assistant --profile profiles/core-v1.json --trust-key independent:"$WORK/keys/reviewer/public.pem" --trust-key self:"$WORK/keys/monitor/public.pem" --scope-id local-readonly --out "$WORK/policy-a.json"
```

Choose the template for the agent (`read-only-assistant`, `code-agent` or `agentic-payments`; see [POLICY-TEMPLATES.md](../POLICY-TEMPLATES.md)). The scope id must equal the `scope.id` in that agent's manifest; the starter manifest from `init` uses `local-readonly`, which is the generator default. The thresholds are starting points and are not validated. Record which template, why, and whether the pilot owner would have chosen different numbers.

### Phase 3: capture rehearsal (simulated)

Goal: see what a verified capture looks like and how a verifier reports findings. The agent here is scripted and simulated.

```sh
node bin/kya.mjs keygen "$WORK/keys/capture"
node scripts/kya-capture.mjs demo --agent careful --key "$WORK/keys/capture/private.pem" --evaluator-key-id EVALUATOR_KEY_ID --now "$NOW" --out "$WORK/capture-careful.json"
node scripts/kya-capture.mjs verify --bundle "$WORK/capture-careful.json" --trust-issuer CAPTURE_KEY_ID
node scripts/kya-capture.mjs demo --agent exfiltrate --key "$WORK/keys/capture/private.pem" --evaluator-key-id EVALUATOR_KEY_ID --now "$NOW" --out "$WORK/capture-exfiltrate.json"
node scripts/kya-capture.mjs verify --bundle "$WORK/capture-exfiltrate.json" --trust-issuer CAPTURE_KEY_ID
```

`EVALUATOR_KEY_ID` is the key id of the evaluator key in your policy (any 64 hex key id from `keygen` output; it must differ from the capture key) and `CAPTURE_KEY_ID` is the key id `keygen` printed for the capture key. Expected, as measured when this kit was written: the careful agent verifies as `"valid": true` with an empty findings list and exit 0; the exfiltrating agent verifies as valid with the findings `exfiltration-attempt` and `probe-failed` and exits 2. Both say `"bound": false` because no pins were given: without all five pins a valid capture of another run also reads clean. Record whether the pilot owner understood that from the output alone.

### Phase 4: assess, check currency, change something

```sh
node bin/kya.mjs assess --manifest "$WORK/agent-a/manifest.json" --profile "$WORK/agent-a/profile.json" --policy "$WORK/policy-a.json" --evidence "$WORK/agent-a/evidence.json" --evaluator EVALUATOR_DIGEST --now "$NOW" --out "$WORK/assess-a"
node bin/kya.mjs currency --assessment "$WORK/assess-a/assessment.json" --manifest "$WORK/agent-a/manifest.json" --policy "$WORK/policy-a.json" --now "$NOW"
```

`EVALUATOR_DIGEST` is the `evaluatorDigest` that `init` printed. With an empty evidence file, expect exit 2 and a decision of `insufficient-evidence` under the starter policy from `init`, or `blocked` under a policy generated from a template (both were observed when this kit was written). That is the right answer for a declaration with no runtime evidence. Record the decision, the blocker codes and what the pilot owner would do with the result. Note that `currency` reported `"current": true` together with `"reliable": false` for such an assessment: current means nothing the check watches has changed, not that the agent qualified.

Now change something and re-check: edit one field in the manifest that keeps it valid (for example replace `configDigest` with another 64 character lowercase hex value; adding a tool outside the scope is refused with exit 1, which is also worth logging), run `currency` again with the same assessment and expect `"current": false`, a `subject-changed` trigger with code `SUBJECT_CHANGED`, `"action": "reassess"` and exit 2. Then write an incident record following the quickstart steps 5 and 6 and observe the `incident` handling. Record any step where the output surprised the operator.

For a pipeline, `node scripts/kya-check.mjs` offers the same checks as a CI gate; see [GITHUB-ACTION.md](../GITHUB-ACTION.md). The pilot does not require a repository, a workflow or any hosted service.

### Phase 5: score card attempt

If the operator has per-item results from their own harness (at least 30 items, 3 repeats, 10 held-out items and a holdout commitment digest), build and verify a card:

```sh
node bin/kya.mjs score build --manifest "$WORK/score-manifest.json" --runs "$WORK/score-runs.json" --out "$WORK/card.json"
node bin/kya.mjs score verify "$WORK/card.json"
```

File formats are specified in [ADR-0033](../adr/0033-kya-score-benchmark-profile.md) and the reproduction steps are in [BENCHMARKS.md](../BENCHMARKS.md). If the floor is not met the build exits 2, writes nothing and names the reasons; log that as a result, do not lower the floor. The card is unsigned, self-run and unvalidated; its fixed non-claim codes say the number does not predict incidents, is not a safety certification and is not a ranking of products. If the operator has no such data, skip this phase and log "no data".

### Phase 6: privacy check and close

Before any file leaves the operator's own control, including to the pilot owner's own colleagues:

```sh
node scripts/privacy-scan.mjs --format text "$WORK/agent-a"
node scripts/privacy-scan.mjs --format text "$WORK/assess-a"
```

Exit 0 means no finding; exit 1 means findings; exit 2 is an error (an unreadable file is never skipped silently). A clean scan is not evidence of absence: the scanner misses names, postal addresses, free text and identifier formats it does not list (see [PRIVACY.md](../PRIVACY.md)). A human must read what will be shared. Then delete the keys and any file the pilot owner does not want kept.

## 7. What is recorded, and what is not

Recorded in the result log (section 10): dates, the commit used, which phases ran, each command's exit code and decision or finding codes, deviations from this kit, questions the operator had to ask, surprises, disagreements, the pilot owner's answers to the closing questions and a stop or complete outcome.

Kept in the workspace, never shared unless the pilot owner approves in writing after the privacy check: manifests, policies, assessments, capture bundles, score cards.

Never recorded anywhere: private keys, credentials, prompts, agent output, customer or personal data, subscription identifiers, file paths that include a person's name.

## 8. Success and stop criteria

**Success** means the process worked, not that an agent is good. The pilot succeeded if all of these hold.

1. Phases 0 to 4 ran to the end from this kit and the linked documents alone, and every question that had to go to the project is in the log.
2. Every command's exit code and decision matched what the documents said, or each difference is logged as a disagreement or surprise.
3. After a manifest change the currency check reported `reassess`.
4. The pilot owner can answer, without looking, these five questions correctly: Does a qualified decision authorize an action? (No.) Does a signature show the agent behaved? (No: bytes and key possession only.) Does a perfect fixture score say anything about the real agents? (No.) Is a report checksum an authentication? (No.) What would make this assessment stale? (Any change the currency check watches, or time.)
5. The privacy scan over everything intended for the pilot owner's colleagues exited 0 and a human read the same files.
6. The pilot owner has stated whether the output would change any decision they actually make: yes, no or unsure, with a reason. The project records the answer and does not interpret it.

**Stop at once** (and log why) if any of these happens:

- Any data leaves the machine, or the operator cannot rule that out.
- A secret, credential or personal record appears in a file in the workspace.
- A command asks for a login, a token, a download or a network connection.
- A privacy scan reports a finding in a file that was meant to be shared.
- The agents' terms of use turn out to forbid the use.
- Anyone describes a result as certification, approval, safe or compliant.
- The stop contact says stop, or the time the pilot owner set aside runs out.
- A suspected security defect in the tool: stop, keep a sanitized reproduction and use the findings template in [REVIEW-KIT.md](../review/REVIEW-KIT.md).

On stop: do not continue to the next phase, do not delete evidence of what happened, record the stop in the log and tell the pilot owner.

## 9. What the pilot can and cannot show

It can show:

- whether a relying party can run the process end to end with the shipped tools;
- where the documentation, error messages or defaults confused a real operator;
- whether the stale-assessment and incident behaviour is understandable;
- whether the vocabulary of decisions, blocker codes and limits is read correctly;
- concrete, reproducible defects and missing features.

It cannot show:

- that any of the agents is safe, reliable or compliant;
- that KYA scores predict real incidents (no calibration data exists);
- that two independent assessors would agree;
- that the project is adopted, endorsed, certified or standard;
- anything about agents that were never run through measured capture;
- that the tool is secure (that needs an outside review; there is none).

One pilot, one organisation, two or three agents, run by people who know the project has been asked to try it, is an anecdote with a log. Treat it that way in every sentence written about it.

## 10. Disagreements, surprises and the result log

Keep one log file in the workspace. Use plain ASCII. Copy the template below and fill it as the day goes; do not reconstruct it afterwards.

- **Disagreement (D):** the tool or a document says one thing and the operator observed another, or two documents differ. Record the exact command, the exact output and the document sentence.
- **Surprise (S):** nothing contradicts a document but the operator did not expect it. Surprises are data about the interface even when the tool is right.
- **Question (Q):** anything the operator had to ask the project owner.

A disagreement about specified behaviour is reported as an issue with the requirement ID and the output; see the reporting steps in [IMPLEMENTERS-GUIDE.md](../IMPLEMENTERS-GUIDE.md). Do not edit a vector, a test or a document to make the log agree. Do not smooth a surprise into a success.

### Result log template

```text
KYA PILOT RESULT LOG

Pilot owner (role, pseudonymous label only):
Operator (role):
Stop contact (role):
Date of start (ISO date):
Repository commit used (full id):
Node version (output of node --version):
Agents in scope (labels only, no product claims): agent-a, agent-b, agent-c or none
Written acceptance of sections 1, 5, 9 and 11 received (yes or no, date):
Written agreement on how questions reach the project (yes or no, date):

PHASE RESULTS (one block per phase and per agent)
Phase:
Agent label:
Commands run (copy exactly, remove paths that contain names):
Exit code of each:
Decision, blocker codes or finding codes printed:
Matches the documents (yes, no, partly):
Notes:

DISAGREEMENTS
D-1: command / output / document sentence / requirement ID if known
D-2:

SURPRISES
S-1: what happened / what was expected / how long it cost the operator
S-2:

QUESTIONS THAT HAD TO GO TO THE PROJECT
Q-1: question / who answered / was the answer in a document (yes or no)

SCORE CARD
Attempted (yes or no):
Result (card, refusal with reasons, or no data):

PRIVACY
Files scanned:
Scanner exit codes:
Files read by a human before sharing:
Anything found by the human that the scanner missed:

CLOSING ANSWERS (pilot owner, in their own words)
Does a qualified decision authorize an action:
Does a signature show the agent behaved:
Does a perfect fixture score say anything about the real agents:
Is a report checksum an authentication:
What makes an assessment stale:
Would the output change any decision you actually make (yes, no, unsure) and why:

OUTCOME
Completed phases:
Stopped (yes or no), at which phase, why:
Defects suspected (list with reproduction paths in the workspace):
Files the pilot owner approves sharing with the project owner (names only):
Approval for any wider use (none unless written separately; copy of the approval):

SIGN-OFF
Pilot owner (label) and date:
```

## 11. No publication without owner approval

No result, score or log from a pilot may be published, quoted in public, announced, posted, submitted or sent to anyone outside the pilot parties without the written approval of the pilot owner and of the project owner, given separately for each item and each use. That includes the existence of the pilot, the name of the organisation, the names of the agents and any number. Approval for one use is not approval for another. Silence is not approval. A draft that has not been approved is not published merely because it exists in a repository.

The project may not describe the pilot as validation, adoption, certification, an endorsement or a customer relationship. If the pilot owner approves a statement, it must carry the limits in section 9.

This kit does not authorize publishing, tagging, releasing, announcing or contacting anyone. Those remain owner decisions taken outside this document.

## 12. Data handling

- Data in scope is limited to manifests, policies, evidence and assessment files, capture bundles and score cards the operator creates in the workspace. None should contain a prompt, customer data or a secret.
- Free text fields are the main risk. Prefer coded values. The signed artifacts carry digests of details, not narrative.
- Hashing a low entropy personal value does not hide it. See [PRIVACY.md](../PRIVACY.md).
- Retention is the pilot owner's decision. Default at the end: delete keys, delete capture bundles, keep only the result log and what the pilot owner approves keeping, and record what was deleted.
- If any personal data is found, stop (section 8), do not copy it into the log, and follow the pilot owner's own incident process.
