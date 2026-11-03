# ADR-0050: Run the full CI matrix once per pull-request update

**Status**: Implemented locally; pending hosted event validation and owner review
**Date**: 2026-11-03

## Context

The workflow ran on every push and every pull-request update. For an internal feature branch with an open PR, a pushed commit therefore scheduled two copies of the same Node 22/24 by Ubuntu/macOS matrix: eight pre-merge jobs instead of four. The completed push and PR workflows for the PR #51 head each contain four successful jobs. Later candidates have been waiting on macOS jobs while their Linux jobs pass. These observations establish duplicate scheduled work, not the cause of every queue delay or a measured latency/cost saving.

## Decision

Keep `pull_request` unfiltered so PRs targeting main or stacked feature branches run the complete matrix. Restrict push events to `main` and all tags. Feature pushes without a PR do not schedule this workflow; local checks remain required, and opening/updating the PR schedules hosted verification. Preserve every matrix value, permission, pinned action and verification step byte-for-byte.

The existing #52–#57 candidates keep their original checks and require every pending check to finish successfully. No old run is cancelled or treated as passed. A new candidate using this workflow has one complete four-job PR matrix before promotion; all observed current-head checks must succeed. Main and tag pushes continue to run the complete four-job matrix. The protected release workflow is unchanged and no tag, release or deployment is created.

GitHub's [workflow syntax documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) defines push branch/tag filters separately from pull-request events.

## Alternatives

- Cancel duplicate running checks: rejected for this change; it would alter existing candidates' evidence and gates.
- Remove an operating system, Node version, mutation suite or regression step: rejected; this is an event-scheduling change, not reduced coverage.
- Run only on feature pushes: rejected; PR merge-context checks are useful, including for forks and stacked branches.
- Add cancellation-based concurrency: deferred; cancellation semantics introduce a separate gate-reconciliation problem.

## Consequences

For one feature update with one PR event, defined pre-merge jobs fall from eight to four. Including a subsequent main push, defined jobs fall from twelve to eight. These are event/matrix counts, not measured runtime, queue-time, billing or environmental-performance improvements. Repeated events and reruns can still add work. A feature branch without a PR has no hosted run until a PR is opened; this is an explicit scheduling tradeoff.

Protocol behavior, test expectations, evaluator identity, schemas and public vectors are unchanged. Every PR still needs the complete Node/OS matrix and every verification step. Existing candidates' eight-check gates are preserved; a future scheduling candidate cannot pass with a missing, failed, skipped or pending matrix member.

## Validation

Compare the workflow body beginning with `permissions:` against the parent and require identical bytes, covering the full matrix, pinned actions and steps. Recompute reviewer counts and the portable ADR index; run source/schema/requirements/status and existing release-workflow checks. Hosted PR event validation must show exactly one complete four-job matrix on this new head. It remains a draft until that matrix succeeds. Main/tag event filters follow the documented GitHub syntax; no tag or main push is generated merely to test them. No new tests mirror the two filter lines, and no full local suite for this scheduling-only head is claimed. Queue latency and cost remain unmeasured.
