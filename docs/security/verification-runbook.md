# Verification runbook

Everything in this repository is proven by the local test suite. The behaviour
that only a live Elastic Stack 9.5.7 can prove is listed here, with the exact
command or UI action that proves it.

Nothing in this file is optional for a production rollout: the mesh makes
security decisions, so each row below is a gate.

## Preflight

| Check | Command | Expected |
| --- | --- | --- |
| Stack version | `curl -s $KIBANA_URL/api/status \| jq -r '.version.number'` | `9.5.7` or newer |
| Workflows feature | `curl -s $KIBANA_URL/api/workflows?per_page=1 -H "kbn-xsrf: true"` | HTTP 200 |
| Endpoint roles | `python scripts/setup.py --validate` | `Elasticsearch API` and `Kibana API` both print a version; a URL that answers the wrong product fails here |
| Credentials | `python scripts/setup.py --validate` | every target reports a mode (`api key` or `user/password`), and both endpoints answer with their own version |
| Connectors | `curl -s $KIBANA_URL/api/actions/connectors -H "kbn-xsrf: true"` | `oputils-virustotal`, `oputils-abuseipdb` |
| Local suite | `python -m pytest tests/ -q` | green, no failures |

## Live behaviour to prove

| # | What | How | Expected |
| --- | --- | --- | --- |
| 1 | Deploy converges | Run `python scripts/setup.py --workflows-only` twice | the second run updates, it does not duplicate |
| 2 | Delete is scoped | `python scripts/setup.py --delete-workflows` (dry run) | lists only workflows tagged `oputils-mesh`; deletes nothing |
| 3 | Delete really deletes | `python scripts/setup.py --delete-workflows --yes` | the tagged workflows are gone, the untagged ones stay |
| 4 | `elasticsearch.request` | Trigger `Check Field Availability` | the step returns the ES body directly (`output.hits.hits`, `output.<field>`), no `data` wrapper |
| 5 | `kibana.request` | Trigger `Get Case Details` | the step returns the Kibana body directly (`output.data.title`) |
| 6 | `cases.createCase` | Trigger `Create Case` | `steps.create_case.output.case.id` matches the case opened in the UI |
| 7 | `cases.updateCase` | Trigger `Update Case Status` | the status changes and the version stays consistent (optimistic concurrency) |
| 8 | `cases.addAlerts` | Trigger `Add Alert To Case` | the alert shows up in the case, attached as an alert and not as a comment |
| 9 | `cases.addComment` | Trigger `Add Case Comment` | the comment is visible in the case timeline |
| 10 | `security.setAlertStatus` | Trigger `Mark Alert As Closed` | the alert closes with the reason that was sent |
| 11 | `security.setAlertTags` | Trigger `Add Alert Tag FP` | the tag list shows the added tag |
| 12 | `security.enableRule` / `disableRule` | Trigger `Enable Disable Rule` | the console reports the number of rules that changed |
| 13 | `ai.agent` | Trigger `Dispatch Monitor` with a pending dispatch | the agent answers and `steps.<name>.output` carries the answer |
| 14 | Enrichment connector | Trigger `VT IP Report` | the connector call succeeds with the key held in Kibana, and no key appears in the workflow YAML |
| 15 | Approval decision | Create a case, request an approval, comment `APPROVED`, then comment something unrelated | the dispatch is queued once, the later comment does not lose the decision |
| 16 | Approval negative | Comment `NOT APPROVED` | the request stays pending, it is not treated as an approval |
| 17 | Index bootstrap | Run the `Create Agent Registry Index` workflow against an empty stack | the index is created (the fallback of the check step); against an existing index the workflow skips the creation and says that the index already exists |
| 18 | Rule editing on 9.5.7 | Edit a rule with a workflow that owns the rule | no `api key has been invalidated` error (the 9.5.7 fix, #300667) |
| 19 | Force delete | Delete a workflow with `--yes` | the workflow is removed even when it is referenced, and the run log says so |
| 20 | No credential echo | Trigger any workflow and read the run log | the `Authorization` header value never appears in the step output |
| 21 | Document removal | Trigger `Remove Knowledge Document` with an existing id and then with a missing one | the first run reports the document as removed, the second reports it as not found and does not fail the workflow |

## Delivery plan

The branch `feat/security-remediation-auditoria` carries 23+ commits and about
5,300 changed lines, which is too much for a single review. The commits are
already ordered so they can be reviewed as five stacks:

1. **Workflow migration** (native request types, `security.*`, `cases.*` steps)
   — the behavioural core, one commit per area.
2. **Deploy and connectors** (idempotent import, real delete, manifest,
   enrichment connectors).
3. **Guards and CI** (secret guard, workflow reference guard, full suite,
   seed and validator coverage).
4. **Authentication modes** (API key or user and password, plus the CI fix
   that was already broken on `main`).
5. **Docs** (9.5.7 alignment, least privilege, remediation record, this
   runbook).

Each stack is self-contained and green on its own: `python -m pytest tests/ -q`
and `ruff check .` pass at every commit.

## Related documents

- `docs/security/least-privilege.md` — the minimum privileges and the two
  authentication modes.
- `docs/security/remediacion-auditoria.md` — what each audit finding changed
  and what is still open.
- `docs/elastic-platform-reference.md` — the step catalogue and the 9.5.7
  alignment.
