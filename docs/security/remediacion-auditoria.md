# Security audit remediation

This document closes the five findings of the security audit of the Elastic
Security Agent Mesh, in the order they were reported. Each row states what the
finding was, where it lived, what changed, how the change is verified, and
what is still open.

Everything below was implemented on the branch
`feat/security-remediation-auditoria`. The baseline was captured before any
code was touched (task T1 of `odd/tasks/security-remediation.md`).

## Summary

| # | Finding | Where | Changed | Verified by | Still open |
|---|---|---|---|---|---|
| R1 | API keys written into workflow definitions | `workflows/**` (114 `http` steps), `scripts/setup.py:933-951` | Every call to Elasticsearch or Kibana now uses a native step (`elasticsearch.request`, `kibana.request`), which takes the credential from the Kibana execution context. The placeholder substitution (`build_replacements` / `apply_replacements`) was removed from `scripts/setup.py`; the workflow YAML is imported verbatim. Third-party keys live in Kibana connectors. The alert and rule mutations were later moved to the `security.*` domain steps (generally available since 9.5). | `tests/test_workflow_secrets.py` (4 tests) fails the build on any legacy placeholder, any authentication header, or any secret-looking constant; `grep` over `workflows/` finds no `Authorization`, `x-apikey`, `Key` or `__*_API_KEY__`; `scripts/validators/workflows.py` rejects any step type it does not know, including the ones nested in control-flow bodies. | Key rotation in Kibana is still manual (see "Open items"). |
| R2 | Deploy was not idempotent and `--delete-workflows` did nothing | `scripts/setup.py:946-951`, `:977-1047`, `:1050-1168`, `:1864` | Import looks the workflow up by name and `oputils-mesh` tag and issues a `PUT` instead of a duplicate `POST`. `--delete-workflows` deletes, dry-run by default and only with `--yes`, and only workflows carrying the `oputils-mesh` tag. `.oputils/workflows-manifest.json` records name → id → path and reports orphans, stale and missing entries. `--delete-all` now deletes the tagged workflows too. | `tests/test_deploy_idempotency.py` (11 tests) with a fake Kibana client: two deploys leave one workflow and the second one `PUT`s; dry-run deletes nothing; a delete with `--yes` removes the tagged workflow and leaves the untagged one; an unreadable workflow list aborts the import instead of posting blind; a `409` without an id is reported as a failure; a manifest entry that is no longer deployed is reported as stale. | The force-delete path (`force=true&acknowledgeAclLoss=true`) was not exercised against a live cluster. |
| R3 | CI ran a fraction of the suite; seeds and validators had no tests | `.github/workflows/ci.yml:55` | The CI job now runs `python -m pytest tests/ -v` instead of `pytest tests/test_setup.py -v`. New tests cover the idempotency and error branches of `scripts/seed_mitre.py`, `scripts/seed_ecs.py`, `scripts/seed_rules.py`, and every error branch of the validators in `scripts/validators/`. | 135 tests pass locally (plus 1 expected failure that pins a known gap in `seed_rules`). The CI job is the same command. | The expected failure in `seed_rules` (no document `id`) is still open. |
| R4 | OpenWebUI documentation claimed a working integration | `docs/superpowers/**/2026-05-06-elastic-openwebui-*` | Both documents carry `Estado: NO IMPLEMENTADO — ningún runtime depende de esto`, and the plan's false footer ("All tasks have complete code") states that the code was written and later deleted. | `grep -rni openwebui` over `scripts/`, `.github/`, `workflows/`, `agents/` and `tests/` returns no runtime reference. | None. |
| R5 | Retry exhaustion left no trace; the deploy identity was undefined | `workflows/mesh/dispatch-monitor.yaml:116-176` | The exhausted branch is now selected from the persisted document state (the dispatch is re-read after the retry script writes it) instead of the stale pre-update snapshot, the failure log no longer claims the dispatch was reset for retry, and the exhausted branch posts a Case comment — the alerting channel this repo already uses. The minimum privilege set for the runtime and deploy identities is documented. | `tests/test_dispatch_retry_alert.py` (5 tests) asserts that the alert action lives inside the agent-failure branch, that the exhaustion decision does not read the stale snapshot, and that the log no longer claims a retry. | The `ai.agent` step type could not be verified server-side. |

## Stack 9.5.7 alignment

The stack was pinned to 9.5.7 after the audit remediation.

- **Requirement.** 9.5.7 is the minimum because it fixes rules edited by a workflow failing with
  `api key has been invalidated` (Kibana #300667) — the path taken by `create-detection-rule`,
  `update-detection-rule` and `enable-disable-rule`.
- **Domain steps.** `security.setAlertStatus`, `security.setAlertTags`, `security.enableRule` and
  `security.disableRule` (generally available since 9.5) replaced the REST calls in
  `mark-alert-as-acknowledged`, `mark-alert-as-closed`, `add-alert-tag-fp`, `add-alert-tag-tp` and
  `enable-disable-rule`.
- **Validator.** `scripts/validators/workflows.py` now fails on an unknown step type — including the ones
  nested inside `if` / `foreach` / `parallel` bodies — and knows the `security.*` and `cases.*` families.
- **Still open.** The five case workflows still call `/api/cases` through `kibana.request`. The `cases.*` steps
  are the typed replacement, but their per-step output shape is not documented, so that conversion is deferred
  to a later increment. `approval-monitor.yaml` still polls case comments instead of using the 9.5 case
  triggers, and the mesh keeps its own `approval-requests` index instead of `waitForApproval` (Preview).

## Verification

An independent read-only review of the destructive deploy path (`scripts/setup.py`
and `tests/test_deploy_idempotency.py`) confirmed the safety properties and
found three gaps that were closed before the branch was finished:

- the dry run really is a dry run: `delete_workflows()` returns before any
  `DELETE` and the real deletion needs `--yes`;
- a workflow without the `oputils-mesh` tag can never be deleted, because the
  tag is the only selection criterion;
- the delete URL is
  `/api/workflows/workflow/{id}?force=true&acknowledgeAclLoss=true`, using the
  id that Kibana reported.

The gaps that were closed:

1. an unreadable workflow list fell back to a blind `POST` for every
   workflow, which is the duplicate bug the change was meant to remove. The
   import now aborts when Kibana answers but the list cannot be read, and only
   continues when Kibana is unreachable, where a `POST` cannot succeed anyway;
2. a `409` without an id was counted as "updated" and never recorded in the
   manifest, so the deploy silently never converged. It is now a reported
   failure, and the import fails loudly;
3. the manifest was written before it was read, which made the stale-entry
   report dead code. The previous manifest is now read first, the file is
   written atomically, and a read or write error is a warning instead of a
   crash.

The review also noted that the test double was stricter than the real API
(uniqueness of the workflow name). The new tests close that gap: the import
aborts on an unreadable list, a `409` without an id, a stale manifest entry, a
corrupt manifest, and both the dry run and the `--yes` path of the CLI.

## Audit findings that did not match the code

The audit predated the current implementation; these points were wrong and were
corrected in the report rather than in the code:

- "Duplicate workflows must be deleted by hand" (`README.md:226-232`): the
  importer already handled `409` with a `PUT`. It was not idempotent by design,
  but it did not create the duplicates the audit described.
- "`--delete-all` does not delete workflows": true, and it was not a
  documentation error — the help text promised something the code never did.
  It is implemented now.
- "Workflows use generic `http` steps instead of native step types": the
  importer and the validator already knew `elasticsearch.request` and
  `kibana.request`, but no workflow used them.

## Open items

These could not be closed from the repository and are stated explicitly:

1. **Key rotation** is manual in Kibana. The procedure is in
   `docs/security/least-privilege.md` (section "Key rotation"). The old keys
   are still valid until an operator rotates them.
2. **The `ai.agent` step type was not verified server-side.** There is no
   local Kibana and no test harness for agent invocation; the conversion kept
   those steps untouched, but the runtime behaviour of the multi-agent flow is
   unverified.
3. **The real content of `.env` was not read.** Only the variable names are
   known; the file is not readable under the current tooling policy. The
   deploy therefore depends on the environment variables listed in
   `.github/workflows/deploy.yml`.
4. **The API key Kibana stores for a workflow** is the credential of the last
   user who saved it. Editing a workflow in the Kibana UI with an
   administrator key leaves that key attached to the workflow. This is
   documented as an accepted operational risk in
   `docs/security/least-privilege.md` (section "Residual risk"), together with
   the rule that workflows are only ever saved by the deploy identity.

## Pre-existing findings that were not fixed

These are defects found while auditing the converted workflows. They existed
before this remediation and are outside the scope of the five findings, so
they were left untouched:

1. `workflows/security/enrichment/ip-reputation-check.yaml` reads the AbuseIPDB
   score with two different paths: the report block uses
   `steps.check_abuseipdb.output.data.data.abuseConfidenceScore` and the
   threat assessment uses
   `steps.check_abuseipdb.output.data.abuseConfidenceScore`. The second path
   is one level short, so the `HIGH RISK` / `MEDIUM RISK` branches never
   trigger and the workflow always reports `LOW RISK`.
2. The `condition: 'steps.<name>.status: "success"'` pattern used by the
   index-creation workflows in `agents/setup/` was written for the legacy
   `http` step. It is kept as is because `.status` is a framework-level
   step attribute, but it was not verified against a live Kibana.

## Version note

The native step types used by the conversion (`elasticsearch.request`,
`kibana.request`, `http` with a `connector-id`) are generally available from
Elastic Stack 9.4 and in preview in 9.3. The `security.*` domain steps are
generally available from 9.5. The repository requires 9.5.7, because 9.5.7
fixes rules edited by a workflow failing with `api key has been invalidated`.
