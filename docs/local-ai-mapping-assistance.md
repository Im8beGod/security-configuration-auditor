# B4 local AI mapping assistance

Local AI is optional and disabled by default. Normal audits and manual mapping authoring do not invoke it.

## Configure

Run Ollama locally with an installed model (preferred: `qwen2.5-coder:7b-instruct-q4_K_M`). The model name is configurable; there is no automatic download or cloud fallback.

Set these backend environment variables and restart the backend:

```dotenv
AI_MAPPING_SUGGESTIONS_ENABLED=true
AI_MAPPING_PROVIDER=ollama
AI_OLLAMA_BASE_URL=http://localhost:11434
AI_OLLAMA_MODEL=qwen2.5-coder:7b-instruct-q4_K_M
AI_OLLAMA_TIMEOUT_SECONDS=120
```

For the existing Docker Desktop development Compose setup, use `http://host.docker.internal:11434`. The runtime must be reachable from the backend container. The native backend defaults to localhost. Settings accept only local origins and reject credentials, redirects and cloud model tags. Configure Ollama for local-only operation; do not use aliases backed by cloud models. No T5 deployment files are changed.

The adapter uses Ollama's [chat endpoint](https://docs.ollama.com/api/chat) with a [JSON schema response format](https://docs.ollama.com/capabilities/structured-outputs), streaming disabled, no tools, temperature zero, 6,000 output tokens, a 96 KiB response cap and bounded generation. `AISuggestionProvider` remains the replacement boundary for another local provider.

## Review workflow

1. Open an unresolved item in Review Center. Refresh availability if Ollama was just started.
2. Select **Suggest with local AI**. Only redacted bounded evidence, selected structural context, profile metadata, the bounded canonical catalog and the DSL schema are sent. Each of the three evidence/context excerpts is limited to 2,048 characters; at most 64 relevant fields are included (bounded registry fallback when no candidates exist). Control characters are normalized, obvious CLI/XML credentials and private-key blocks are redacted, and redaction/truncation flags are shown. Other published mappings and tenant identifiers are excluded from the prompt.
3. Review the returned evidence excerpt, definition, explanation, advisory confidence and caveats. Schema/DSL/applicability checks do not establish semantic correctness.
4. **Discard** leaves no mapping. **Use as draft** is the explicit authenticated write: it creates an AI-assisted draft with provenance. Preview requests make no database writes.
5. Run existing executable validation. XML validation uses the referenced artifact when available; the full editor also allows explicit evidence selection. Review candidate facts/effective states before approval and publication using the existing B3 lifecycle.

Prompt `mapping-suggestion.v2` is built deterministically. The raw `ModelMappingProposal` schema permits only definition, description, confidence and caveats. Model-supplied lifecycle/provenance properties are rejected. Server metadata records provider/model, prompt version, timestamp, profile, input SHA-256 and raw-response SHA-256. Source artifact identifiers are attached by the server and preserved on adoption.

Malformed, oversized, incomplete, tool-calling, incompatible or unavailable responses fail safely. Raw failed model output is not returned or stored. Manual authoring remains available. Adoption uses a 30-minute signed token bound to the user, tenant, unresolved block and evidence fingerprint, with a separate signing-key domain from login tokens. The row lock and assigned-mapping check prevent duplicate adoption. Changing a draft follows existing validation invalidation behavior. No migrations are needed.

## Verification and acceptance

Provider-independent unit checks:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/unit/test_local_ai.py tests/unit/test_training.py -q
```

The focused PostgreSQL test uses a new test tenant inside a rolled-back outer transaction. Configure development PostgreSQL settings, then run:

```powershell
$env:SIH_TRAINING_POSTGRES_TEST = '1'
.\.venv\Scripts\python.exe -m pytest tests/integration/test_local_ai_postgres.py -q
```

For real Ollama acceptance, additionally set `SIH_REAL_OLLAMA_TEST=1` and the native local URL/model. The real XML case calls the actual adapter with bounded development unresolved evidence through the backend API, validates its response, explicitly adopts it through the API, and runs the B3 executable validator. It asserts candidate SecurityFacts/EffectiveStates exist while normal fact/state tables remain unchanged. It never approves or publishes. A bad model output fails the test; there is no fake fallback. Do not alter the implementation just to fit generated output.

Implementation-session results: 57 focused unit/regression tests passed; PostgreSQL CLI lifecycle and XML API/adoption/candidate-fact/state tests passed (2 tests), with the real Ollama case skipped; 3 frontend render/API contract tests and the frontend build passed. Frontend lint reports two existing MappingEditorPage React warnings. Real-runtime acceptance is **pending**: Ollama was not found on PATH and localhost:11434/api/tags was unreachable. No model response or held-out result is claimed. B4 is not sealed, committed or pushed.


Frontend focused checks: `node --test tests/local-ai.test.mjs`, `npm run build`, `npm run lint` from `frontend/`.

Migration head/current remain `20260908_0013`; B4 adds no schema changes. The requested Alembic drift check reports existing baseline differences: the model declares `ix_profile_manifest_versions_organization_id` absent from migration 0013/the database, and the database profile-resolution snapshot FK is RESTRICT while checked-in migration/model specify CASCADE. B4 does not alter those unrelated tables or historical constraints. This is a reported pre-existing drift finding, not a clean drift check.
