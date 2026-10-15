# Calibration study design: do KYA decisions precede real incidents?

Status: Draft design (WS10-04). Written by the project authors. It has had no statistician review, no external review and no counsel review. Related: [WORLD-CLASS-PLAN.md](WORLD-CLASS-PLAN.md), [PRIVACY.md](PRIVACY.md), [ADR-0014](adr/0014-signed-incident-and-appeal-records.md), [ADR-0021](adr/0021-capture-issuer-role-and-campaign-ledger.md), [ADR-0023](adr/0023-scenario-suites-and-holdout-commitments.md), [SCORING.md](SCORING.md), [BENCHMARKS.md](BENCHMARKS.md), [CALIBRATION-PREREGISTRATION-TEMPLATE.md](CALIBRATION-PREREGISTRATION-TEMPLATE.md).

## Statement of evidence status

No data exists yet, and nothing in this document is evidence of predictive validity.

This file describes a study that has not been run, not been funded, not been registered and not been reviewed. The numbers in it are planning arithmetic under stated assumptions, not findings. No real model, agent or vendor has been run for it. Predictive validity is stage 7 of the world-class plan and is not claimed anywhere in this repository.

## Purpose

Question: among deployed agent configurations that KYA assessed before deployment, does the KYA decision order them by the chance of a later independently recorded incident better than chance, and better than cheaper signals a relying party already has?

A positive answer would be a statement about one sample, one period and one population. It would not be a statement that KYA prevents incidents, that a qualified agent is safe, or that the ordering holds elsewhere (see Threats to validity). A negative or inconclusive answer is an acceptable and useful result and will be published with the same prominence.

## Hypotheses

Stated before any data exists. Direction is one-sided because only a higher incident rate for worse KYA standing would be useful; an inverted ordering is reported and counts toward REJECT.

Primary (H1): the ordinal KYA risk order (blocked above insufficient-evidence above qualified, ties by mid-rank) has a Mann-Whitney AUC greater than 0.5 for the primary outcome within the primary window. Null: AUC at most 0.5. Minimum useful value, used for power and for the ACCEPT rule: AUC 0.60.

Secondary, tested in this fixed order, each only if the one before passed (fixed-sequence gatekeeping):

1. S1: the KYA ordering has a higher AUC than the declaration-only baseline (paired difference greater than 0).
2. S2: where a vendor benchmark score exists for enough agents (at least 60 percent of the analysis set, set in the registration), the KYA ordering has a higher AUC than the vendor benchmark score on the agents that have one.
3. S3: the same AUC advantage as H1 holds for the severe-outcome definition (critical severity only).

Descriptive only, no test and no claim: incident rate per decision category with Wilson 95 percent intervals, windows of 90 and 365 days, the insufficient-evidence stratum alone, rate per unit of reported exposure, and the leave-one-vendor-out sensitivity of H1.

## Outcome definitions

Outcomes must be measured independently of the assessed agent and of KYA. The following are fixed here and restated in the registration.

Primary event: a `kya.incident/v1` record of kind `report` with severity `high` or `critical` (ADR-0014), whose subject digest matches the agent's frozen subject digest, dated inside the follow-up window and signed by a key that the study policy lists as an unrevoked anchor with role `independent`. The reporting key must belong to a party that is not the agent operator, not the assessor, not the capture issuer and not the study authors, declared by the registrar before enrolment. Records signed by any other key are ignored and counted in a missing-and-ignored table, as ADR-0014 already requires.

Severe event (S3): the same, `critical` only.

What the outcome cannot establish: that an incident is true, complete, or caused by the agent. A signature proves key possession and a record exists; it does not prove the facts in the record (AGENTS.md). The incident record carries only a digest of private details, so an event is "a trusted report exists", not "harm occurred".

Resolution handling: the primary analysis counts every trusted report whether or not it was later resolved, because an ADR-0014 resolution does not distinguish an unfounded report from a remediated one. The sensitivity analysis removes reports that a blinded outcome-adjudication panel, recorded in the private study dataset, classifies as unfounded. The panel is blinded to the KYA decision and to the baselines. No new ledger or record kind is introduced for this.

Incident source requirement: at least two independent reporting channels must be declared before enrolment (for example a relying party and a separate incident registry). A study with a single reporting channel is limited to INCONCLUSIVE, because a channel could be correlated with the assessment.

Ascertainment: an agent with no reporting channel in force for its whole window is missing, not event-free (see Missing data).

## Unit of analysis

One row per agent configuration, identified by its subject digest at the index time. The index time is the signed completion of its assessment run in the enrolment campaign. A vendor with several configurations contributes several rows; clustering by vendor is handled in the variance estimate (Sample size) and in the leave-one-vendor-out sensitivity. The same configuration enrolled twice is one row (the earliest index time).

## Eligible population and exclusions

Eligible: agent configurations that are in production use or committed for production use, with a declared reporting channel, an accountable party, a frozen manifest, a complete assessment under one frozen profile, suite, evaluator and policy digest, and a KYA decision of qualified, blocked or insufficient-evidence at the index time.

Excluded, before looking at any outcome: decision expired or revoked at index time; research-only or fixture agents; agents that the study authors built or operate; agents whose operator saw the held-out cases before assessment; agents assessed under a different frozen profile or policy than the study cohort (they may be added only as a separate, separately registered cohort); agents with no independent reporting channel. The registration records the count excluded for each reason, and any agent dropped after enrolment is listed with the reason.

Enrolment is a complete list committed in advance: the enrolment campaign plan (see the template) lists every planned assessment attempt, so an unfavourable or omitted agent stays a visible planned entry in the campaign counts (ADR-0021). Enrolment that follows the outcomes is not permitted.

## Follow-up windows and censoring

Index time t0. Primary window: 180 days from t0. Descriptive windows: 90 and 365 days. Follow-up ends at the earliest of: the primary event, the end of the window, a change to the agent's subject digest, withdrawal of the agent from production, or loss of its reporting channel.

Subject digest change: any change in configuration that produces a new subject digest ends follow-up for the old digest at the change date. The new digest is not a continuation. It may be enrolled as a new unit only if the new configuration is itself assessed before any outcome is known for it, under the same cohort rules; it never inherits the old decision. A change is detected only if the operator or a trusted record reports it; agents whose digest is not re-attested at the planned checkpoints (day 30, 90, 180) are flagged and handled as missing.

Withdrawal after a blocked or insufficient-evidence decision is not neutral: removing a poor agent from production removes its chance of an incident. The primary analysis therefore counts only agents with a complete window or an earlier event (event-or-complete set), and two bounding analyses are pre-specified, one treating withdrawn agents as events and one as non-events. If the two bounds lead to different ACCEPT, REJECT or INCONCLUSIVE outcomes, the result is INCONCLUSIVE.

## Baselines

All baselines are fixed in the registration and computed on the same analysis set and index time.

1. Random: AUC 0.5 by definition; also a permutation reference with 10,000 shuffles of the decision labels under a fixed seed recorded in the registration.
2. Declaration-only: an ordinal score from the manifest declarations alone (declared scope, declared controls, declared accountable party), computed by a rule fixed before data; this is the baseline for S1. It uses no observed evidence.
3. Vendor benchmark score: where a vendor or a public benchmark supplies a numeric score for the configuration at or before t0, its rank order. Missing for many agents; S2 is run only if the coverage condition in the hypotheses holds, otherwise S2 is reported as not testable and the sequence stops.
4. A simple rule baseline: operator-reported prior incident count in the 12 months before t0, which is a known cheap signal. Reported descriptively.

A benchmark baseline is not the KYA evaluator and no vendor is named in any public output without the vendor right of reply required elsewhere in the plan.

## Sample size reasoning

Test: one-sided test of AUC against 0.5 at alpha 0.025, power 0.80, using the Hanley and McNeil variance of the Mann-Whitney AUC under the null (0.5) and the alternative. Calculation: the required number of agents N is the smallest N with prevalence pi such that z(0.975) * SE0 + z(0.80) * SE1 is at most (AUC1 - 0.5), where z(0.975) = 1.960, z(0.80) = 0.842, n1 = pi * N events, n0 = (1 - pi) * N non-events, and SE(A) is the square root of [A(1-A) + (n1-1)(Q1 - A^2) + (n0-1)(Q2 - A^2)] divided by n1*n0, with Q1 = A/(2-A) and Q2 = 2A^2/(1+A).

Results under independence of agents (computed with a script that is not part of the repository; recompute before registration):

| True AUC | pi = 0.05 | pi = 0.10 | pi = 0.20 |
| :--- | ---: | ---: | ---: |
| 0.60 | 1406 (71 events) | 740 (74 events) | 414 (83 events) |
| 0.65 | 624 (32 events) | 328 (33 events) | 183 (37 events) |
| 0.70 | 347 (18 events) | 183 (19 events) | 102 (21 events) |
| 0.75 | 218 (11 events) | 115 (12 events) | 64 (13 events) |

Assumptions, all unverified: the event prevalence pi over 180 days is unknown and may be well below 0.05 for high or critical severity; agents are independent, which is false when one vendor fields several configurations (a design effect of 1.5 is applied below as a placeholder, not a measured value); the Hanley and McNeil approximation assumes a roughly binormal score, whereas the KYA ordering has three ordinal levels with many ties, so the variance is probably larger and DeLong or bootstrap intervals must be used in the analysis; attrition, withdrawal and missing data reduce the analysis set.

Planning value used in this design: AUC1 = 0.65, pi = 0.10, design effect 1.5, and 20 percent attrition. Analysis set at least 492 agents (328 times 1.5) and enrolment at least 615 (492 divided by 0.8), with at least 33 events before the primary analysis is allowed to return ACCEPT or REJECT.

S1, the paired comparison, is larger. For a baseline AUC of 0.60 against 0.70 with a correlation of 0.5 between the two AUC estimates, the same method needs 745 agents at pi = 0.10 (1,043 at correlation 0.3, 448 at 0.7), before the design effect and attrition. A study sized only for H1 is underpowered for S1, and the registration must say so.

Feasibility is not supported today. The project has no cohort, no reporting channel, no design partner agreement and no incident source. Reaching several hundred assessed production agents with an independent incident channel needs relying-party partners at a scale the project has not demonstrated. The first private campaign (WS10, three configurations) is a harness exercise, not a pilot of this study. If the achievable cohort is far smaller than the table requires, the honest outcomes are to narrow the question (a larger effect threshold, a longer window, or a pooled registry across organisations) or not to run the study; the design must not be rescaled after seeing data. A study that cannot reach the minimum events is reported as INCONCLUSIVE and the achieved number of events and its confidence interval are published.

## Analysis plan

One final analysis after the 180-day window of the last enrolled agent has closed. No efficacy interim analysis and no stopping for apparent efficacy or futility.

Primary: Mann-Whitney AUC of the ordinal KYA risk order against the primary event on the event-or-complete analysis set, with a two-sided 95 percent interval from a cluster bootstrap by vendor (fixed seed, 10,000 resamples, recorded in the registration); the DeLong interval is reported as a check. Secondary comparisons use the paired DeLong test or the paired cluster bootstrap; the registration names which one is primary for each.

Reporting: counts of planned, enrolled, completed, withdrawn, digest-changed, ignored-record and missing agents (the campaign summary counts are the denominator source), event counts per decision category, all intervals, and every deviation from the registration with its date.

## Handling configuration change

Covered in Follow-up windows and censoring: a subject digest change ends follow-up for that digest. The study does not interpret post-change incidents as outcomes for the old digest, and does not attribute them to the new digest unless that digest was separately assessed beforehand. Dependency or model-provider updates that do not alter the declared subject digest are an unmeasured source of drift and are listed as a threat.

## Missing data

Primary rule: agents with no reporting channel in force for the full window, and agents lost to follow-up without a recorded reason, are missing. They are excluded from the primary set and reported by decision category. Two bounds are pre-specified: all missing agents as non-events, and all as events. No imputation model is used for the headline result. If the missing proportion exceeds 20 percent of the enrolled agents, or differs by more than 10 percentage points between decision categories, the result is INCONCLUSIVE regardless of the estimate. Missing data does not move an agent out of the planned denominator count.

## Multiplicity

One primary hypothesis at alpha 0.025 one-sided. S1, S2 and S3 are tested in the fixed sequence above, each at the same alpha, stopping at the first failure; no later hypothesis is tested after a failure. The descriptive items carry no test and are not used to support a claim. Any analysis not listed here is exploratory, labelled so, and cannot change the ACCEPT, REJECT or INCONCLUSIVE outcome.

## Decision rules fixed before seeing data

Let the primary set contain E events, with E_min = 33, N_min = 492 analysis agents (both from the planning value above, replaced by the registered values if the registration changes them with the reasoning recorded before data).

ACCEPT: all integrity gates pass (below), E is at least E_min and N at least N_min, the lower bound of the two-sided 95 percent interval for the primary AUC is above 0.50, the point estimate is at least 0.60, S1 passes (paired difference lower bound above 0), and both withdrawal bounds lead to the same classification. ACCEPT means only that the pre-specified criteria were met in this sample. It does not establish predictive validity in general, causation, safety of any agent, or that KYA should be relied on in another population.

REJECT: all integrity gates pass, E is at least E_min, and the upper bound of the two-sided 95 percent interval for the primary AUC is below 0.60 (including any inverted ordering with the whole interval below 0.50). REJECT means the data exclude a useful effect size in this sample. It is published and the ordering and wording of any claim are revisited.

INCONCLUSIVE: everything else. This includes too few events or agents, a failed integrity gate, a single reporting channel, missing data beyond the stated limits, disagreement between the withdrawal bounds, a primary interval that spans 0.60 together with values at or below 0.50, a primary pass with a failed S1, and any material protocol deviation judged so by the registrar before unblinding the result. INCONCLUSIVE is not a soft ACCEPT and is not reported as supportive.

Integrity gates: the registration hash was recorded in the signed campaign ledger before the first cohort assessment run; the campaign ledger verifies with an externally pinned head; no holdout case revealed before follow-up closed was used in an assessed decision; assessments were not shown to operators or relying parties during follow-up, or the shown stratum is analysed separately and the headline uses the unshown stratum only; at least two independent incident channels were active.

## Threats to validity

Selection: agents whose operators agree to be assessed and to report incidents differ from the population; better-run organisations may both qualify more often and report more. The estimate applies only to the enrolled population.

Survivorship and attrition: poor agents are withdrawn early; incidents of withdrawn agents never occur. Addressed only by the bounding analyses, not eliminated.

Goodhart and gaming: once decisions gate deployment or procurement, operators tune to the public suite. The study uses the protected holdout commitment where one exists (ADR-0023) but commit-reveal does not prevent leakage before reveal, does not prove the cases are representative and does not prove a campaign ran them. A result from before KYA is used for gating says little about the result after.

Holdout leakage: a holdout case that becomes known to an operator or a training pipeline before follow-up closes invalidates that case for the study; the integrity gate covers it.

Outcome contamination by the assessment itself: a blocked agent may be monitored more closely, restricted, or withdrawn, changing its chance of a reportable incident; a qualified agent may be given wider scope. Exposure and scope are not randomised. This is a threat to any causal reading and the study makes no causal claim. Reporting channels that learn the KYA decision may report differently; operators and channels are kept blind during follow-up as far as the integrity gate allows.

Confounding: agent complexity, deployment volume, domain and operator maturity affect both the KYA decision and the incident chance. Only descriptive stratification is planned; no adjusted analysis is pre-specified for the headline.

Measurement: the independent reporting key set can be incomplete, captured, or correlated with the assessor; incident severity labels are assigned by reporters with differing standards; a signature proves a key signed, not that the event occurred.

Evaluator drift: a change to the frozen evaluator, profile or policy mid-study starts a new cohort; the original cohort is not re-scored.

Multiple looks and forking paths: guarded by the single final analysis, the fixed sequence and the freeze-and-hash registration. A registration hash that was not recorded before data collection voids the integrity gate and the result is INCONCLUSIVE.

Small-sample fragility: with few events, one reclassified incident can change the outcome; sensitivity to adding or removing one event is reported.

## Data governance and privacy

The study dataset is digest-only and coded: subject digests, vendor pseudonymous codes held privately, decision codes, incident record digests, severity codes, dates. No prompts, responses, traces, names or free text. Narrative incident details stay with the reporting party under its own access control; only the digest travels (ADR-0014). Raw evidence bundles stay in the private campaign directory with owner-only permissions and are not part of the study dataset. The vendor code mapping is held separately from the analysis dataset. See [PRIVACY.md](PRIVACY.md) for the redaction order, the low-entropy digest warning (a digest of a guessable value confirms the guess) and retention rules, and [DPIA-TEMPLATE.md](DPIA-TEMPLATE.md) for the assessment to complete before any data is collected; privacy counsel review is required. Retention period, deletion and the right of a vendor to withdraw before the window closes are set in the registration.

Who may see interim results: the outcome data and any interim counts are sealed. Only a named data steward who is not a study author and not an assessed or reporting party may see them, and only for data-quality and safety questions (for example an apparent serious incident needing a duty-to-report decision under the incident process). No efficacy figure, no event count by decision category and no estimate is shown to the study authors, operators, relying parties or the public before the final analysis is unblinded, the final analysis code is frozen and its hash is recorded. A breach of this rule is a protocol deviation and is reported.

Publication of any result, vendor-identifying or not, needs explicit human authorization and counsel review for naming and right of reply (AGENTS.md, WORLD-CLASS-PLAN.md). Results are published whatever their direction.

## Operational boundaries

This design involves no model run, no agent run, no network call and no publication. Running the study needs separate human authorization, an approved budget, relying-party agreements, a privacy review and a statistician and an independent reviewer who have not yet been engaged.

## What is not established

No data exists. The power calculation rests on guessed prevalence and effect size. The design has not been reviewed by a statistician, an epidemiologist, a privacy professional or counsel. Feasibility of the cohort is not shown. The independence of the proposed incident channels is not shown. Nothing here is evidence of predictive validity, of the usefulness of any KYA decision, or of the safety of any agent.
