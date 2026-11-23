# Least-privilege credentials

This repo deploys two different things, and they need two different identities:

1. **Runtime identity** — the credential the Kibana workflow engine uses when a
   workflow executes. Workflows in this repo call `elasticsearch.request`,
   `kibana.request` and `cases.*` steps, so the credential attached to a
   workflow must be allowed to do exactly that.
2. **Deploy identity** — the API key used by `scripts/setup.py` to create
   indices, import workflows, create Agent Builder tools/agents and register the
   connectors.

Never use a `superuser` key for either. The sets below are the minimum this
repo needs; anything not listed here is out of scope on purpose.

This describes Elastic Stack 9.5.7.

## 1. Runtime identity (workflow execution)

| Capability | Needed for | Minimum |
| --- | --- | --- |
| Read/write the repo indices | `elasticsearch.request` steps | `read`, `write`, `create_index` on the indices listed below |
| Read/write cases | `kibana.request` steps that POST to `/api/cases/...` | `cases:write` (includes comment + status) |
| Read/write detection rules | `kibana.request` steps that hit `/api/detection_engine/rules`, plus `security.enableRule` and `security.disableRule` | detection rules read + write, including rule enable/disable |
| Read/write alerts | `kibana.request` steps that hit `/api/detection_engine/signals/...`, plus `security.setAlertStatus` and `security.setAlertTags` | alerts read + write, including alert status and alert tag management |
| Execute response actions | `kibana.request` steps that hit `/api/endpoint/action/...` | endpoint response-action execute |
| Run the workflow | workflow execution | `workflowsManagement:execute` |

The `security.*` steps (generally available since 9.5) carry the same privileges as the REST calls they
replace: alert status, alert tags, and rule enable/disable are authorized separately. Elastic also authorizes
alert mutations per rule type — the 9.5.7 release notes fix a bug where bulk alert untracking ignored those
boundaries — so a role that manages alerts for one rule type must not be assumed to manage another.

Cases as Data is enabled by default from 9.5, so case analytics land in their own indices. No workflow in this
repo reads them; grant read access to the `.ds-cases-*` indices only if an analytics workflow is added.

### Elasticsearch indices in scope

Read/write only these:

```text
action-policies
agent-metrics
agent-registry
approval-requests
dispatch-requests
investigation-contexts
kb-compliance
kb-detection-rules
kb-incidents
kb-mitre-attack
kb-playbooks
.alerts-security.alerts-default
.alerts-security.alerts-*
```

The `.alerts-security.alerts-*` read access is the only access the workflows
need to the Security alerts data; the workflows never need `all` on the
Security application.

### Explicitly out of scope

- `all` on the Kibana application.
- `all` on the Security application (detection rules, alerts, cases and
  endpoint actions are granted individually above).
- Cluster administration (`manage`, `monitor` on everything, `manage_security`).
- Any index not listed above, including `.security*`, `.kibana*` and the
  internal `.elastic*` indices.

### Outbound third-party calls

`workflows/security/enrichment/vt-*.yaml` and
`workflows/security/enrichment/ip-reputation-check.yaml` call VirusTotal and
AbuseIPDB through Kibana HTTP connectors (`oputils-virustotal`,
`oputils-abuseipdb`). The credential lives in the connector secret, not in the
workflow and not in this role. The connectors must be allowed to reach
`www.virustotal.com` and `api.abuseipdb.com`; on a locked-down cluster set
`xpack.actions.allowedHosts` accordingly.

## 2. Deploy identity (`scripts/setup.py`)

The deploy key needs, on top of the runtime set:

| Capability | Needed for |
| --- | --- |
| `workflowsManagement:read`, `:create`, `:update`, `:delete` | listing, importing, updating and deleting workflows (including `--delete-workflows`) |
| Agent Builder tools and agents read/write | creating the tools in `agents/definitions/` and the agents in `agents/setup/` |
| Connectors read/write | creating and updating the `oputils-virustotal` and `oputils-abuseipdb` HTTP connectors |
| Elasticsearch `create_index`, `bulk`, `index` | creating the repo indices and seeding the knowledge base |

This identity is the one that stores credentials in Kibana, so it is the one to
rotate first and to keep out of day-to-day use. Use it only from CI.

### Authentication modes

Every target (Elasticsearch, Kibana) authenticates in one of two modes:

| Mode | Variables | Notes |
| --- | --- | --- |
| API key | `ES_API_KEY`, `KIBANA_API_KEY` | Scoped, revocable, and the mode Elastic recommends for machine-to-machine calls. |
| User and password | `ES_USERNAME` + `ES_PASSWORD`, `KIBANA_USERNAME` + `KIBANA_PASSWORD` | Every call is attributed to a named identity in the Kibana and Elasticsearch audit logs. |

The API key wins when both modes are configured for the same target. A username
without its password is rejected: the setup aborts with an explicit message
instead of sending an anonymous request.

When you use the user and password mode, use a dedicated native user with a
scoped role — never the `elastic` superuser — and treat the password like any
other secret: store it in the CI secret store and rotate it. The password does
not expire on its own, and unlike an API key it also works interactively, so
it is the weaker of the two options unless the audit trail is the goal.

This choice only affects the deploy identity (`scripts/setup.py` and the seed
scripts). It does not change how the workflows authenticate at runtime: they
run with the credentials Kibana attaches to the execution context, never with
the deploy credentials.

## 3. Residual risk (accepted and documented)

**Kibana stores the credential of the last user who saved a workflow.** When a
workflow is edited in the Kibana UI, Kibana records that user's credentials
with the saved object. Consequences:

- A workflow imported by the deploy key keeps the deploy key attached.
- If an administrator edits a workflow in the UI, the workflow now runs with
  the administrator's credentials until it is re-imported.
- There is no way to strip the stored credential from a saved object other
  than re-importing it with the intended identity.

Accepted, with two operational rules:

1. Only the deploy identity may save workflows. Day-to-day edits happen in git.
2. After any UI edit of a workflow, re-run the deploy so the workflow runs with
   the least-privilege identity again.

## 4. Key rotation

Rotation is manual in Kibana (there is no automation for it in this repo):

1. Create the new key for the runtime identity and the deploy identity.
2. Update the secrets in the deployment environment
   (`ES_API_KEY`, `KIBANA_API_KEY`, or the user and password pair) and in the
   connectors' secrets.
3. Re-import the workflows (`python scripts/setup.py`) so the saved objects
   carry the new credential.
4. Revoke the old keys.
5. Confirm the workflows still execute (`python scripts/setup.py --validate`,
   then trigger one workflow manually).
