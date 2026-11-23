# Feature: Security remediation of the Elastic agent mesh audit

Correct the five audit findings in the order the user gave, keeping the deploy green.
Phase 0 (baseline) is complete: this document is the handoff for the implementation phases.

## Specs

S1 — Objective and order
> "OBJETIVO: corregir los 5 riesgos que devolvió la auditoría de seguridad, en este orden, sin romper el deploy. Aplicá las REGLAS del prompt anterior."

S2 — Phase gating
> "No avances a la fase siguiente hasta que la anterior esté con tests en verde. Reportá al final: qué cambiaste, qué tests agregaste, qué NO pudiste verificar."

S3 — Phase 0 baseline
> "FASE 0 — BASELINE (no escribir código todavía): leer y reportar el estado real de [workflows/mesh/dispatch-monitor.yaml (consts, step types, on-failure/retry), scripts/setup.py (mecanismo de import, flags, placeholders __ES_API_KEY__/__KIBANA_API_KEY__), .github/workflows/ci.yml, tests/ (qué testea qué; qué validadores y seed_*.py sin cobertura), scripts/validators_*.py y scripts/seed_*.py, y docs/superpowers/ (openwebui)]. Entregar una tabla: archivo:línea → qué hace hoy → qué hay que cambiar → riesgo."

S4 — Phase 1b: native step types
> "1b Para cada step que hoy pega la clave en un `http` contra ES o Kibana: convertilo al tipo nativo equivalente (elasticsearch.search, elasticsearch.index, elasticsearch.esql.query, kibana.cases, kibana.request). Los tipos nativos toman la credencial de la API key que Kibana guarda internamente → no hace falta tocar el YAML con ninguna clave. Si algún caso no tiene equivalente nativo, NO lo resuelvas metiendo la clave en `consts`: documentá el caso y las alternativas."

S5 — Phase 1c/1d: setup.py and tags
> "1c setup.py: eliminar el mecanismo de sustitución de placeholders (que hoy permite que la clave llegue al YAML). 1d Sumar el tag `oputils-mesh` a todos los workflows que importa el repo (para poder borrarlos después de forma segura)."

S6 — Phase 1e/1f: rotation and guard test
> "1e ROTAR las claves de ES y Kibana en Kibana (podés documentar el procedimiento, no lo ejecutes contra el cluster). 1f Test de regresión: recorrer workflows/**/*.yaml y fallar si encuentra `__ES_API_KEY__`, `__KIBANA_API_KEY__` o un valor con forma de credencial en consts/headers (heurística: prefijo de key conocida, o string 20+ alfanuméricos pegado a nombre de variable de secreto). El test tiene que correr en CI."

S7 — Phase 2: idempotent deploy
> "2a --delete-workflows de verdad: listar workflows (GET /api/workflows, paginado), filtrar por tag `oputils-mesh`, borrar (DELETE /api/workflows/workflow/{id}?force=true&acknowledgeAclLoss=true). Dry-run por default; el borrado real solo con un flag explícito (--yes). Nunca tocar workflows que no tengan el tag. 2b Import idempotente: antes de importar cada YAML, buscar por nombre+tag entre los workflows existentes: si existe, PUT /api/workflows/workflow/{id}; si no, POST /api/workflows. Nunca POST a ciegas. 2c Manifest: guardar el mapeo nombre→id de los workflows importados (ej. `.oputils/workflows-manifest.json`) para poder detectar orphans y reportarlos. 2d Test: con un cliente HTTP falso (responses/mock), dos deploys seguidos dejan 1 workflow (no 2) y el segundo deploy hizo PUT (no POST). Test del dry-run de --delete-workflows."

S8 — Phase 3: CI and coverage
> "3a .github/workflows/ci.yml: correr la suite completa (`python -m pytest tests/ -v`) con las dependencias que el repo ya usa. 3b Tests para cada scripts/seed_*.py (mínimo: idempotencia — correr dos veces no duplica documentos). 3c Tests para los validadores sin cobertura (un caso por rama de error). 3d El guard de secretos (1f) tiene que correr en CI y fallar el build si aparece una credencial en un workflow. 3e Criterio de aceptación: CI corre la suite completa, el conteo de tests sube y la cobertura no baja."

S9 — Phase 4: OpenWebUI as plan only
> "FASE 4 — OPENWEBUI (riesgo #4): tratarlo como PLAN, no como feature. ... Mover los docs de openwebui a docs/plans/ (o dejar el doc con nombre/first line explícita 'Estado: NO IMPLEMENTADO — ningún runtime depende de esto'). Verificar con grep que ni setup.py, ni ci.yml, ni ningún workflow referencie openwebui (si algo lo referencia, ese es el bug real: corregirlo). NO reescribir historia de git ni amends."

S10 — Phase 5: permissions and retry alerting
> "5a El import debe usar una API key de cuenta de servicio / rol acotado. Definí el set mínimo en un doc de operación: workflowsManagement read+create+update+delete, Cases write, lectura de los índices de alertas que usa el repo, workflowsManagement:execute. Fuera de scope: `all` de Kibana y Security `all`. Dejar escrito el residual (Kibana guarda la API key del último que guardó el workflow → editar en la UI con admin deja esa key almacenada) como riesgo operacional accepted pero documentado. 5b Retry sin alerta (dispatch-monitor.yaml:133): hoy el reintento agota los intentos y no deja rastro. Al agotar intentos debe dejar rastro — ELEGÍ UNA vía según lo que ya usa el repo (Case comment, documento en índice, o log con nivel error) y justificá en una línea por qué no las otras dos. 5c Test del on-failure: al menos un test que verifique que la definición del workflow tiene la acción de alerta en el on-failure final (no sólo la config de retry)."

S11 — Phase 6: closing document
> "FASE 6 — CIERRE: escribir docs/security/remediacion-auditoria.md con tabla: hallazgo → archivo:línea → qué cambió → cómo se verifica → qué queda abierto. Listar explícitamente como abiertos: rotación de claves (manual en Kibana), verificación server-side del step type ai.agent, contenido real de .env (solo nombres de variables), y el comportamiento de la API key almacenada por Kibana ante ediciones manuales en la UI."

## Conversion contract

Authoritative rules for Phase 1b. Derived from Kibana 9.4 source (`workflows_execution_engine/server/step/{elasticsearch_action_step,kibana_action_step,connector_step}.ts`,
`server/lib/call_kibana_api.ts`, `stack_connectors/server/connector_types/http/http_connector.ts`) and the official
step docs. Do not deviate; if a file does not fit, stop and report instead of improvising.

### C1. Step types

| Target of the current `http` step | New step type | `with` shape |
|---|---|---|
| URL contains `{{ consts.es_url }}` or `__ES_URL__` | `elasticsearch.request` | `method`, `path`, `body` (path = URL path only, relative to the ES root) |
| URL contains `__KIBANA_URL__` or `{{ consts.kibana_url }}` | `kibana.request` | `method`, `path` (starts with `/`), optional `body`, optional `query` (object), optional `headers` (custom only) |
| URL is a third-party host with a credential in `consts` | `http` + `connector-id` | `path` (relative to the connector base URL), `method`, `body`, optional `query`, optional non-auth `headers` |
| URL is a third-party host without any credential | `http` (unchanged) | `url` unchanged |

The `connector-id` key sits at the step top level (sibling of `with`), never inside `with`. The connector base URL lives in
Kibana (connector config), so `with.path` is relative to it:

| Connector | Base URL | Step `path` example |
|---|---|---|
| `oputils-virustotal` | `https://www.virustotal.com/api/v3` | `/domains/{{ inputs.domain }}` |
| `oputils-abuseipdb` | `https://api.abuseipdb.com/api/v2` | `/check` (query: `{ipAddress: "{{ inputs.ip_address }}"}`) |

`elasticsearch.request` and `kibana.request` take their credential from the workflow execution identity; never put
`Authorization`, `kbn-xsrf`, `elastic-api-version` or any API key in them. `kibana.request` auto-adds `kbn-xsrf` and
`Content-Type`.

### C2. Path and query mapping

- ES: `{{ consts.es_url }}/{{ consts.alerts_index }}/_search` → `path: /{{ consts.alerts_index }}/_search`.
  `__ES_URL__/kb-mitre-attack/_search` → `path: /kb-mitre-attack/_search`. The ES root is implicit.
- Kibana: `__KIBANA_URL__/api/detection_engine/rules/_find?per_page=1000&sort_field=name&sort_order=asc` →
  `path: /api/detection_engine/rules/_find` + `query: {per_page: 1000, sort_field: name, sort_order: asc}`.
  Query strings never stay inside `path`.
- Kibana query values keep their templates: `?rule_id={{ inputs.rule_id }}` → `query: {rule_id: "{{ inputs.rule_id }}"}`.
- A conditional query fragment keeps its Liquid expression inside the query value:
  `{% if inputs.search %}&filter=alert.attributes.name:%20{{ inputs.search }}{% endif %}` →
  `query: { filter: "{% if inputs.search %}alert.attributes.name: {{ inputs.search }}{% endif %}" }`.

### C3. Output references

The legacy `http` step wrapped the parsed body in `.output.data`. `elasticsearch.request` and `kibana.request` expose
the body directly. Therefore, for every **ES or Kibana** step converted to a native type, in the whole file:

    steps.<name>.output.data  →  steps.<name>.output

(drop exactly one `.data`; any further `.data` belongs to the response body itself and stays).
Examples: `steps.list_rules.output.data.total` → `steps.list_rules.output.total`;
`steps.isolate.output.data.data.id` → `steps.isolate.output.data.id`;
`steps.search.output.data.hits.hits` → `steps.search.output.hits.hits`.
Steps that are not converted keep their references untouched (`ai.agent`, `console`, `http` without conversion).

A step converted to `http` + `connector-id` keeps the legacy shape (the http connector result is
`{status, statusText, headers, data}`, body at `.data`): its references are NOT rewritten.

### C9. Every reference is rewritten, not only the obvious ones

`steps.<name>.output.data` appears in console messages, `if` conditions, `foreach` inputs, body strings and
`on-failure` blocks, not only in obvious assignments. Search the whole file for the step name and rewrite every
occurrence that belongs to a converted ES/Kibana step. References to `ai.agent`, `console` or non-converted steps
stay exactly as they are.

### C4. Timeouts

`timeout` is not a `with` field anymore: move it to the step top level as a duration string
(`with: {timeout: 600}` → step-level `timeout: "600s"`; `timeout: "30s"` → step-level `timeout: "30s"`).
This applies to every converted step, including `http` + `connector-id` (the http connector has no timeout
parameter; the step-level timeout is the only control).

### C5. Third-party credentials

Third-party API keys never live in the workflow YAML. They move to a Kibana connector secret:

- VirusTotal → connector `oputils-virustotal` (base URL `https://www.virustotal.com/api/v3`, secret header `x-apikey`).
- AbuseIPDB → connector `oputils-abuseipdb` (base URL `https://api.abuseipdb.com/api/v2`, secret header `Key`).
- `ip-api.com` needs no credential: it stays a plain `http` step with its full URL.

The workflow step keeps `connector-id: <connector name>` at the step top level and drops only the auth header;
every other header (for example `Content-Type`) stays in `with.headers`. The connector itself is provisioned by
`scripts/setup.py` (task T3); the workflow only references it by name.

### C6. Consts cleanup

After conversion, `es_url`, `es_api_key`, `kibana_url`, `kibana_api_key`, `vt_api_key` and `api_key` (AbuseIPDB) are
dead. Remove each const only if no remaining reference to it exists in the file; remove the whole `consts:` block when
it becomes empty. Non-secret consts (index names, base URLs of keyless third parties, agent names) stay.

### C7. Tags

Every workflow imported by the repo gets the tag `oputils-mesh` (task T3 adds it at import time; the YAML files keep
their own tags).

### C8. What must not change

Step names, step order, `if`/`foreach` control flow, `on-failure` blocks, triggers, inputs, descriptions and the
semantics of every request. This phase only changes how a request is issued and how its output is read.

## Tasks

| ID | Spec | Task | Route | Status | Commit |
|---|---|---|---|---|---|
| T1 | S3 | Baseline audit + native step contract | parent | done | this document |
| T2 | S4 | Convert `http` steps to native step types (57 workflow files) | worker x4 (disjoint folders) | done | `38d75df`, `bc710b2`, `a64b76c` |
| T3 | S5 | setup.py: drop placeholder substitution, add `oputils-mesh` tag, provision third-party connectors | parent | done | `c897c84` (tag: `38d75df`, `bc710b2`, `a64b76c`) |
| T4 | S6 | Secret guard regression test + CI wiring | parent | done | `f63a047`, `8971167` |
| T5 | S7 | Idempotent deploy: PUT by name, real `--delete-workflows`, manifest, tests | parent | done | `c897c84` |
| T6 | S8 | CI full suite + tests for seed_*.py and validators | worker | done | `8971167` |
| T7 | S9 | OpenWebUI marked as plan, not implemented | parent | done | docs commit |
| T8 | S10 | Minimal-permissions doc + retry alerting with a verifiable test | parent | done | `bc710b2` (workflow), `f63a047` (test), docs commit (least privilege) |
| T9 | S11 | `docs/security/remediacion-auditoria.md` + final report | parent | done | docs commit |

## Log

L1 (2026-11-20, user, original request)
> "OBJETIVO: corregir los 5 riesgos que devolvió la auditoría de seguridad, en este orden, sin romper el deploy. Aplicá las REGLAS del prompt anterior."
> "FASE 0 — BASELINE (no escribir código todavía): leer y reportar el estado real de [workflows/mesh/dispatch-monitor.yaml (consts, step types, on-failure/retry), scripts/setup.py (mecanismo de import, flags, placeholders __ES_API_KEY__/__KIBANA_API_KEY__), .github/workflows/ci.yml, tests/ (qué testea qué; qué validadores y seed_*.py sin cobertura), scripts/validators_*.py y scripts/seed_*.py, y docs/superpowers/ (openwebui)]. Entregar una tabla: archivo:línea → qué hace hoy → qué hay que cambiar → riesgo. Si algo de la auditoría no coincide con lo que ves en el código, decilo: la auditoría puede estar desactualizada."
> "FASE 1 — SECRETOS EN LOS WORKFLOWS (riesgo #1) — 1a Inventariá los YAML que usan __ES_API_KEY__/__KIBANA_API_KEY__ o que meten credenciales en consts/headers. 1b Para cada step que hoy pega la clave en un `http` contra ES o Kibana: convertilo al tipo nativo equivalente (elasticsearch.search, elasticsearch.index, elasticsearch.esql.query, kibana.cases, kibana.request). Los tipos nativos toman la credencial de la API key que Kibana guarda internamente → no hace falta tocar el YAML con ninguna clave. Si algún caso no tiene equivalente nativo, NO lo resuelvas metiendo la clave en `consts`: documentá el caso y las alternativas. 1c setup.py: eliminar el mecanismo de sustitución de placeholders (que hoy permite que la clave llegue al YAML). 1d Sumar el tag `oputils-mesh` a todos los workflows que importa el repo (para poder borrarlos después de forma segura). 1e ROTAR las claves de ES y Kibana en Kibana (podés documentar el procedimiento, no lo ejecutes contra el cluster). 1f Test de regresión: recorrer workflows/**/*.yaml y fallar si encuentra `__ES_API_KEY__`, `__KIBANA_API_KEY__` o un valor con forma de credencial en consts/headers (heurística: prefijo de key conocida, o string 20+ alfanuméricos pegado a nombre de variable de secreto). El test tiene que correr en CI."
> "FASE 2 — DEPLOY IDEMPOTENTE (riesgo #2) — 2a --delete-workflows de verdad: listar workflows (GET /api/workflows, paginado), filtrar por tag `oputils-mesh`, borrar (DELETE /api/workflows/workflow/{id}?force=true&acknowledgeAclLoss=true). Dry-run por default; el borrado real solo con un flag explícito (--yes). Nunca tocar workflows que no tengan el tag. 2b Import idempotente: antes de importar cada YAML, buscar por nombre+tag entre los workflows existentes: si existe, PUT /api/workflows/workflow/{id}; si no, POST /api/workflows. Nunca POST a ciegas. 2c Manifest: guardar el mapeo nombre→id de los workflows importados (ej. `.oputils/workflows-manifest.json`) para poder detectar orphans y reportarlos. 2d Test: con un cliente HTTP falso (responses/mock), dos deploys seguidos dejan 1 workflow (no 2) y el segundo deploy hizo PUT (no POST). Test del dry-run de --delete-workflows."
> "FASE 3 — CI Y COBERTURA (riesgo #3) — 3a .github/workflows/ci.yml: correr la suite completa (`python -m pytest tests/ -v`) con las dependencias que el repo ya usa. Corré la suite y arreglá lo que rompa; si algo falla y no se puede arreglar sin cambiar alcance, frená y reportá. 3b Tests para cada scripts/seed_*.py (mínimo: idempotencia — correr dos veces no duplica documentos). 3c Tests para los validadores sin cobertura (un caso por rama de error). 3d El guard de secretos (1f) tiene que correr en CI y fallar el build si aparece una credencial en un workflow. 3e Criterio de aceptación: CI corre la suite completa, el conteo de tests sube y la cobertura no baja."
> "FASE 4 — OPENWEBUI (riesgo #4) — tratarlo como PLAN, no como feature. Mover los docs de openwebui a docs/plans/ (o dejar el doc con nombre/first line explícita 'Estado: NO IMPLEMENTADO — ningún runtime depende de esto'). Verificar con grep que ni setup.py, ni ci.yml, ni ningún workflow referencie openwebui (si algo lo referencia, ese es el bug real: corregirlo). NO reescribir historia de git ni amends. Si hay fecha comprometida, la implementación mínima entra en scope pero hay que avisar y esperar confirmación."
> "FASE 5 — PERMISOS Y ALERTING DEL RETRY (riesgo #5) — 5a El import debe usar una API key de cuenta de servicio / rol acotado. Definí el set mínimo en un doc de operación: workflowsManagement read+create+update+delete, Cases write, lectura de los índices de alertas que usa el repo, workflowsManagement:execute. Fuera de scope: `all` de Kibana y Security `all`. Dejar escrito el residual (Kibana guarda la API key del último que guardó el workflow → editar en la UI con admin deja esa key almacenada) como riesgo operacional accepted pero documentado. 5b Retry sin alerta (dispatch-monitor.yaml:133): hoy el reintento agota los intentos y no deja rastro. Al agotar intentos debe dejar rastro — ELEGÍ UNA vía según lo que ya usa el repo (Case comment, documento en índice, o log con nivel error) y justificá en una línea por qué no las otras dos. 5c Test del on-failure: al menos un test que verifique que la definición del workflow tiene la acción de alerta en el on-failure final (no sólo la config de retry)."
> "FASE 6 — CIERRE: escribir docs/security/remediacion-auditoria.md con tabla: hallazgo → archivo:línea → qué cambió → cómo se verifica → qué queda abierto. Listar explícitamente como abiertos: rotación de claves (manual en Kibana), verificación server-side del step type ai.agent, contenido real de .env (solo nombres de variables), y el comportamiento de la API key almacenada por Kibana ante ediciones manuales en la UI."
> "No avances a la fase siguiente hasta que la anterior esté con tests en verde. Reportá al final: qué cambiaste, qué tests agregaste, qué NO pudiste verificar."

L3 (2026-11-23, correction) — Verified against `connector_step.ts` and `http_connector.ts` in Kibana main:
the http connector executor returns `{status, statusText, headers, data}` and the step exposes that object, so a
step converted to `http` + `connector-id` keeps the legacy `.output.data` body shape and its references must not be
rewritten. Only ES and Kibana native conversions drop one `.data`. Also confirmed: `connector-id` is read from the
step top level (`step['connector-id']`), and the http connector merges `params.headers` over the connector config
headers, so non-auth headers survive in `with.headers`.

L2 (2026-11-23, decision) — Phase 1b target types: `elasticsearch.request` for Elasticsearch calls and
`kibana.request` for Kibana REST calls, chosen over the named actions (`elasticsearch.search`, `cases.*`) because the
named actions change the request body contract and their output shape cannot be verified offline; `kibana.request`
keeps the REST call and its body byte-identical and only changes who attaches the credential. Third-party keys move to
Kibana connectors (`oputils-virustotal`, `oputils-abuseipdb`) because this stack has no VirusTotal connector type and
the HTTP connector can hold secret headers.

L4 (2026-11-23, progress) — Phase 1b runs as four parallel writers with disjoint surfaces
(`workflows/security/detection/**`; `workflows/security/enrichment/**` + `workflows/security/response/**`;
`workflows/investigation/**` + `workflows/knowledge/**` + `workflows/mesh/**` + `workflows/utilities/**`;
`workflows/governance/**` + `workflows/feedback/**` + `workflows/compliance/**` + `workflows/observability/**` +
`workflows/search/**`). The golden conversion (`workflows/utilities/isolate-host.yaml`) is already applied and
`python -m scripts.validators.workflows` is green. Phase 1c (drop the placeholder substitution from `scripts/setup.py`)
runs in parallel on `scripts/setup.py` + `tests/test_setup.py`.

The credential guard of S7 now exists as `tests/test_workflow_secrets.py` and is RED until every workflow is
converted: it fails on any legacy placeholder (`__ES_API_KEY__`, `__KIBANA_API_KEY__`, `__VT_API_KEY__`,
`__ABUSEIPDB_API_KEY__`, `__LLM_CONNECTOR_ID__`, `__ES_URL__`, `__KIBANA_URL__`), on any authentication header
(`authorization`, `x-apikey`, `key`, …) and on any constant whose name looks like a secret but carries a value.

Phase 4 (S9) is closed: both OpenWebUI documents carry `Estado: NO IMPLEMENTADO — ningún runtime depende de esto`,
the false footer claim ("All tasks have complete code") is qualified, and `grep -rni openwebui` over `scripts/`,
`.github/`, `workflows/`, `agents/` and `tests/` finds no runtime reference.

The `oputils-mesh` tag (S6) is added to the 57 workflow YAMLs in one pass after the conversion lands, so
`scripts/setup.py` imports every workflow already tagged and the delete-by-tag of Phase 2 can select them safely.

L5 (2026-11-23, close) — The five phases are implemented and the suite is green (135 passed, 1 xfailed).
Commits on `feat/security-remediation-auditoria`, in order:
`38d75df` (security workflows), `bc710b2` (platform workflows and the dispatch retry alert),
`a64b76c` (index bootstrap workflows), `f63a047` (secret guard and retry alert tests),
`8971167` (CI, seed and validator tests), `c897c84` (idempotent deploy and connector provisioning),
and the documentation commit.
The conversion is larger than one review slice (1834 authored lines), so it was split by area and the
workflow commits carry the transformation, the guard test and the retry test with it.

An independent read-only review of the destructive deploy path found three gaps, all closed before the
branch was finished: an unreadable workflow list no longer falls back to a blind POST, a `409` without an
id is a reported failure instead of a silent "updated", and the manifest is read before it is written and
is written atomically. The details are in `docs/security/remediacion-auditoria.md` (section "Verification").

Open, not verifiable from the repository: the manual key rotation in Kibana, the server-side behaviour of
the `ai.agent` step, the real content of the local environment file, and the credential Kibana keeps for the
last user who saved a workflow.
