# Design note: `vuln-scan:enrich` image variant

Status: **proposed, not implemented**.

The base `vuln-scan` image runs the static analysers and emits raw +
unified reports. This variant adds a small local LLM (via Ollama) so an
`--enrich` pass can post-process each finding with:

- a plain-English explanation tied to the snippet,
- a false-positive likelihood (0..1),
- a one-paragraph remediation hint,
- best-effort cross-finding deduplication.

The model runs entirely inside the container (no API key, no network
egress at scan time) so it works in offline / sealed CI environments.

## Why option 2 (bundle in a separate image) over the alternatives

| Option | Image size | First-run | Ongoing | Setup burden |
|---|---|---|---|---|
| 1. Ollama on host VM, image stays lean | ~2 GB | fast | fast | install Ollama once on VM |
| **2. Bundle Ollama + model in `:enrich` image** | ~5 GB | medium (cold pull) | fast | none |
| 3. llamafile (model embedded in single binary) | ~3 GB | medium | medium | model swap is hard |

Option 2 is the friendliest *for sharing*: anyone can
`docker pull ghcr.io/reaandrew/vuln-scan:enrich` and have a working
enrichment pipeline with no other moving parts.

The base `:latest` stays cheap to pull (no LM weights) for users who
only want raw findings.

## Model choice

Default model: **`qwen2.5:3b`** (~2 GB, q4 quantised).

Reasons:
- Apache-2.0; redistributable in the image.
- Strong reasoning for size, code-aware.
- Comfortable on CPU at 8 cores / 16 GB (the devenv VM spec); ~5–15 s
  per finding when prompted concisely.
- Easy to override at runtime: `--model qwen2.5:7b`, `llama3.2:3b`,
  `phi3.5:3.8b`, etc.

## Dockerfile additions (sketch)

A second target in the existing `Dockerfile` (multi-stage) keeps things
tidy:

```dockerfile
# ── Variant: enrich ─────────────────────────────────────────────────────
FROM base AS enrich

# Ollama runtime
RUN curl -fsSL https://ollama.com/install.sh | sh

# Pre-pull the default model so it's baked into the layer
ENV OLLAMA_MODELS=/var/lib/ollama
ARG ENRICH_MODEL=qwen2.5:3b
RUN ollama serve >/tmp/ollama.log 2>&1 & \
    sleep 3 && \
    ollama pull "$ENRICH_MODEL" && \
    pkill ollama

ENV VULN_SCAN_ENRICH_MODEL=$ENRICH_MODEL
ENV VULN_SCAN_OLLAMA_HOST=http://127.0.0.1:11434

ENTRYPOINT ["/opt/vuln-scan/bin/entrypoint-enrich.sh"]
CMD ["--help"]
```

`bin/entrypoint-enrich.sh` would:

1. start `ollama serve &`,
2. wait for `:11434` to respond,
3. exec `scan.sh "$@"` (with the `--enrich` flag implied or honoured),
4. trap signals so Ollama is stopped on exit.

## CI workflow change

Extend `.github/workflows/docker.yml` with a matrix:

```yaml
strategy:
  matrix:
    target: [base, enrich]
steps:
  - uses: docker/build-push-action@v6
    with:
      target: ${{ matrix.target }}
      tags: |
        ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ matrix.target == 'base' && 'latest' || 'enrich' }}
        # plus sha-/version tags as today
```

Cache via GHA so the heavy model-pull layer reuses across builds. The
model layer rarely changes; the app code on top is small.

## scan.sh changes

Add a flag and a post-aggregation step:

```sh
--enrich            run findings through the local LM via Ollama HTTP
--model NAME        override the model (default: $VULN_SCAN_ENRICH_MODEL)
--ollama-host URL   override the Ollama endpoint
```

After `unify.py` runs:

1. read `report.json`,
2. for each finding, build a tight prompt:
   - system: vuln class taxonomy + JSON output schema,
   - user: rule_id, category, file:line, message, snippet, ±10 lines,
3. POST to `/api/generate` (or `/api/chat`) with `format: json`,
4. merge response fields into the finding, write `report.enriched.json`.

Throughput notes:
- batch by file (group findings hitting the same file so context is reused),
- cache by `(rule_id, file, sha256(snippet))` so re-runs are near-free,
- cap concurrency to `nproc / 2` to avoid thrashing.

## Unified schema additions

Each enriched finding gains:

```json
{
  "enrichment": {
    "model": "qwen2.5:3b",
    "false_positive_likelihood": 0.15,
    "explanation": "…plain English, ties the rule to the snippet…",
    "remediation": "…one paragraph fix sketch…",
    "duplicate_of": null
  }
}
```

`duplicate_of` is the `rule_id + file:line` of an earlier finding the
model considers the same root cause; `unify.py` collapses them in
`summary.total_findings_deduped`.

## Image size budget

| Layer | Approx |
|---|---|
| base (debian-slim + scanners + semgrep cache) | ~2.0 GB |
| ollama binary | ~120 MB |
| qwen2.5:3b model (q4) | ~1.9 GB |
| **total `:enrich`** | **~4.0 GB** |

Larger models (7B → 4.5 GB image, 13B → 8 GB) are opt-in via a build
arg if anyone wants stronger triage.

## Open questions

- Do we want enrichment as a separate image or as a flag on `:latest`
  that pulls the model on first run? (Separate image keeps `:latest`
  trim and lets ops decide.)
- Should we publish quantised variants (`q4`, `q8`) as different tags?
- Worth offering an OpenAI-compatible API mode (`--openai-host`) for
  users who want to point at vLLM, llama.cpp's server, or a hosted API?
