# Elastic Agent Platform Reference

This document is the project baseline for designing and reviewing the Security Agent Mesh. It captures verified facts from Elastic's official documentation as of 2026-08-11 (validation pass against the live docs; see "Validation log" at the bottom). It is not a replacement for the linked source documentation, which remains authoritative.

Where this document says "project standard" or "we require", that is a project-derived rule layered on top of what Elastic documents. Project-derived rules are not part of any Elastic contract — re-validate them on every platform upgrade.

## Quick path

1. Model a **workflow** as a typed YAML automation with explicit inputs, steps, outputs, and failure behavior.
2. Model an **agent** as instructions plus the exact tools and skills it is assigned.
3. Model a **tool** as one atomic, typed operation with structured output.
4. Model a **skill** as selectively loaded instructions, relevant tools, and optional reference content for one task.
5. Put destructive or high-impact work behind native workflow approval and verify the action's outcome before reporting success.

## Platform model

| Component | Elastic definition | Project implication |
| --- | --- | --- |
| Workflow | A reusable, versioned YAML recipe triggered manually, on a schedule, or by an event. | Workflows are the execution boundary for mesh actions and integrations. |
| Step | A typed unit of logic or action; outputs become available to subsequent steps. | Every downstream reference must name an actual prior step and its documented output shape. |
| Agent | An LLM with custom instructions, assigned tools, skills, and behavior settings. | An agent prompt must never claim it can call a tool that is not assigned. |
| Tool | An atomic operation with typed inputs and structured results. | Prefer narrow tools over broad generic HTTP or request tools whenever a native tool exists. |
| Skill | A reusable capability pack: instructions, tools, and optional reference context, loaded selectively. | Put shared, task-specific runbooks in skills; reserve prompts for always-on agent behavior. |

## Workflows

### Authoring contract

Workflow YAML contains metadata, optional constants, typed inputs, triggers, and sequential steps. Dynamic values use workflow context:

- `inputs.<name>` for run-specific values.
- `consts.<name>` for definition-time constants.
- `steps.<step_name>.output` for prior step output.
- `steps.<step_name>.error` only when failure handling permits continued execution.

Use `{{ }}` when rendering a string and `${{ }}` when preserving arrays, objects, or numeric types.

### Step selection

Prefer domain steps over generic escape hatches. For example, Elastic provides dedicated case, detection-rule, alert-status, Elasticsearch, and Agent Builder invocation steps. `elasticsearch.request` and `kibana.request` are escape hatches and require a tighter review because their effect is less constrained by their type.

Use `workflow.execute` for synchronous child composition and `workflow.executeAsync` only when the caller does not need the result in the same execution. These composition steps are documented as technical preview; pin and revalidate their behavior before relying on them for a critical control path.

#### Step maturity matrix

The step-type index tags the following steps as Preview. Treat each as high-risk and pin its behavior on every upgrade:

| Step | Status |
| --- | --- |
| `waitForApproval`, `waitForInput` | Serverless Preview, Stack Preview (9.5+) |
| `parallel` | Stack Preview (9.5+), Serverless Preview |
| `entityStore.updateAssetCriticality` | Stack Preview (9.5+), Serverless Preview |
| `workflow.execute`, `workflow.executeAsync`, `workflow.fail`, `workflow.output` | Tech preview |
| `kibana.streams.*` | Tech preview |
| `ai.agent`, `ai.classify`, `ai.prompt`, `ai.summarize` | Generally available but model-dependent |

#### Deprecated steps

The step-type index lists these as deprecated. Replace them in any workflow that still uses them:

- `kibana.createCaseDefaultSpace`, `kibana.getCaseDefaultSpace`, `kibana.updateCaseDefaultSpace`, `kibana.addCaseCommentDefaultSpace` → use the space-aware `cases.*` family.
- `inference.*`, `bedrock.*`, `gen-ai.*`, `gemini.*` → use the `ai.*` step family or the provider's own connector step.

#### Connector steps

Every configured Kibana connector exposes one or more `<connector>.<action>` step types (`slack.postMessage`, `jira.createIssue`, `pagerduty.triggerIncident`, `virustotal.scanFileHash`, ...). Connector steps are typed actions, not generic HTTP — prefer them over `kibana.request` whenever the action matches.

#### Workflows ↔ Cases ↔ Alerts

The practical bridge for an incident response mesh is:

1. `security.setAlertStatus` (or `kibana.SetAlertsStatus`) to acknowledge and triage an alert.
2. `cases.createCase` to open a case, then `cases.addAlerts` to attach the triggering alert(s).
3. Optional `cases.pushCases` to deliver to an external connector (SIEM, ticketing).
4. `cases.updateCase` and `cases.addComment` as the investigation progresses.

Cases have their own `connector_id` for push-to-external and their own RBAC; a workflow that opens a case must own the case for its audit trail to stay coherent.

### Failure behavior

The default on a failed step is to abort the workflow. `on-failure` can be configured per step or as a workflow default, with this precedence:

1. Per-step `on-failure`.
2. `settings.on-failure`.
3. Engine default: abort.

Use retries only for transient failures; condition them on errors such as HTTP 429 or 5xx. Do not use `continue: true` for a mutation whose success is required by later logic. A workflow that must survive a failed mutation should use an explicit fallback or a separate `workflows.failed` handler and must record the failure as such.

### Human approval

Use `waitForApproval` for binary human authorization. It pauses execution and returns a structured approval result, including `response.approved` and `respondedBy`. The mutation must be guarded by the approval result; a rejection does not automatically stop subsequent steps.

Do not use external Slack resume links for destructive, production-impacting, or difficult-to-reverse actions. Elastic documents those links as public and short-lived. For such actions, keep approval in Kibana or require an equivalent authenticated, auditable control. The recommended guard is `if: "steps.<name>.output.response.approved : true"`; document the rejection and timeout branches explicitly so the workflow does not silently proceed past a denied mutation.

For richer human-in-the-loop flows (escalation tickets, plan confirmation, structured JSON-Schema input), use `waitForInput`. It exposes the same `response` shape and timeout semantics as `waitForApproval`.

A workflow that is waiting on human input enters the `WAITING_FOR_INPUT` execution state. Operators should expose this state in any observability view; a stuck workflow is one that never leaves it.

The `workflows.failed` trigger lets a separate handler workflow react after another workflow has failed. The trigger payload exposes the source workflow's name, execution id, and error. A SOC mesh should run a dedicated failure handler that pages on-call, opens a case, and includes the failed execution id in the alert.

### Required mutation pattern (project standard)

The 7-step recipe below is a project-derived minimum bar, not an Elastic-documented contract. Each step is supported by one or more Elastic doc pages (cited inline in the section above), but the sequence itself is the mesh's standard for any destructive or state-changing action.

For destructive or state-changing operations:

1. Validate inputs before any lookup or mutation.
2. Read and show the intended target and scope.
3. Obtain native human approval when policy requires it.
4. Execute the narrowest available action.
5. Fail closed on execution failure.
6. Read the resulting state or consume a documented successful result before reporting success.
7. Record the approval identity, action ID, target, outcome, and execution ID.

## Agent Builder

An agent reasons over a user request, selects from its assigned tools, executes them, evaluates structured results, and repeats until it can respond. The agent's effective capabilities are therefore the intersection of its instructions and assigned tools/skills—not its prose alone.

Custom agents are space-aware. Built-in agents are space-agnostic and cannot be modified; clone a built-in agent to customize it.

The **Enable Elastic capabilities** setting dynamically grants all current and future Elastic-built tools, skills, and plugins. The default differs by agent type: **built-in agents ship with it enabled**; **custom agents ship with it disabled**. For least-privilege specialist agents we require it disabled; the review must approve any change. Review the active Tools and Skills tabs after any change because an enabled toggle silently inherits new tools/skills/plugins released later.

Custom agents are space-scoped to the Kibana space where they were created. Workflows that an agent invokes must be reachable from that space; cross-space dispatch requires explicit operational sign-off.

Direct Tools API calls do **not** receive Agent Builder human-in-the-loop confirmation. API automation must therefore enforce its own authorization and approval boundary.

## Tools

Tools are functions: each should expose a clear purpose, typed inputs, and structured output that an agent can safely reason over.

### Tool design rules

- Give every tool one operation and a precise description.
- Expose only inputs needed for that operation; validate enum-like values at the boundary.
- Return explicit success, failure, stable identifiers, and resulting state when a mutation occurs.
- Assign only the tools relevant to a skill or agent task.
- Treat `elasticsearch.request` and `kibana.request` (the official "escape hatches" in the step-type index) as high-power capabilities requiring strict inputs and governance. Prefer the dedicated domain steps whenever they cover the action.

Some built-in skills can expose inline tools while active. These are not necessarily listed in the global tools reference, so a local catalog must distinguish globally assigned tools from skill-scoped inline tools.

Tools can also be imported from an MCP server ("Copy MCP Server URL", "Bulk import MCP tools"). A mesh that exposes tools via MCP needs to be aware of the known issue in 9.2 where the Copy button omits the space name.

## Skills

Skills are selectively loaded. Their names and short descriptions are always available to the agent for routing, while their full instructions load only after selection.

### Skill design rules

- Scope one skill to one coherent task.
- Make descriptions semantically distinct and state exactly when the skill applies.
- Start instructions with concrete trigger conditions.
- Include ordered procedure, expected output shape, realistic examples, and edge cases.
- Put lengthy or conditional material in named `referenced_content` blocks.
- Associate only the tools needed by that task.
- Test that the agent selects the skill when expected, follows the steps correctly, and handles the documented edge cases.

#### Skill hard limits (from the custom-skills reference)

- **Name:** max 64 characters.
- **Description:** max 1024 characters.
- **Associated tools:** up to 100 per skill.

Plan skill boundaries and tool assignments to stay inside these limits; the platform enforces them at create/update time and a rejected save is not a soft warning.

Use system prompts only for short, universal agent behavior. Move reusable or detailed task procedures into skills.

## Catalog review checklist

### Agent definitions

- [ ] Every named tool is actually assigned, or explicitly documented as skill-scoped.
- [ ] Always-on policy and identity instructions are in the agent prompt; task procedures are in skills.
- [ ] Dynamic Elastic capabilities are disabled unless explicitly justified.
- [ ] The agent documents its escalation and no-tool fallback behavior.

### Skill definitions

- [ ] Description is distinct from nearby skills and names concrete triggers.
- [ ] Instructions include procedure, output, and edge cases.
- [ ] Associated tools are minimal and match all tool references in the instructions.
- [ ] Referenced content is current, named, and shallowly structured.

### Workflow definitions

- [ ] Inputs are typed and validated before use.
- [ ] Each step type is current and selected over a generic escape hatch where possible.
- [ ] Mutation paths abort on failure and verify final state before success output.
- [ ] Approval paths use `waitForApproval` or an equally authenticated, auditable mechanism.
- [ ] Approval rejection and timeout branch away from the mutation.
- [ ] Retries apply only to transient, bounded failures.
- [ ] Technical-preview steps are isolated and tracked for version revalidation.

## Official sources

- [Elastic Workflows overview](https://www.elastic.co/docs/explore-analyze/workflows)
- [Workflow step types](https://www.elastic.co/docs/explore-analyze/workflows/reference/step-types)
- [Pass data and handle errors](https://www.elastic.co/docs/explore-analyze/workflows/authoring-techniques/pass-data-handle-errors)
- [`waitForApproval` step](https://www.elastic.co/docs/explore-analyze/workflows/steps/wait-for-approval)
- [`waitForInput` step](https://www.elastic.co/docs/explore-analyze/workflows/steps/wait-for-input)
- [Human-in-the-loop techniques](https://www.elastic.co/docs/explore-analyze/workflows/authoring-techniques/human-in-the-loop)
- [Event-driven triggers (incl. `workflows.failed`)](https://www.elastic.co/docs/explore-analyze/workflows/triggers/event-driven-triggers)
- [Workflows setup and RBAC](https://www.elastic.co/docs/explore-analyze/workflows/get-started/setup)
- [Agent Builder agents](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/agent-builder-agents)
- [Agent Builder tools](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/tools)
- [Skills in Agent Builder](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/skills)
- [Custom skills](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/custom-skills)
- [Skill creation guidelines](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/skill-creation-guidelines)
- [Token usage in Agent Builder](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder/monitor-usage)
- [Security cases (workflow bridge)](https://www.elastic.co/docs/solutions/security/investigate/security-cases)

## Next step

Use this reference to rewrite the highest-risk workflows around native approval, least-privilege tools, and verified mutation outcomes before extending the agent catalog.

## Validation log

- **2026-08-11** — Initial draft, 9 official sources fetched live and verified. All claims cross-checked against the source pages. Added: step maturity matrix, deprecated steps, connector steps, workflows↔cases↔alerts bridge, `waitForInput`, `workflows.failed` trigger, RBAC link, MCP server note, hard skill limits, Enable Elastic capabilities default per agent type, custom agent space scoping. Relabeled the Required mutation pattern as a project standard. Trimmed the "Test positive triggers" bullet to match the three things the official guide actually lists.
