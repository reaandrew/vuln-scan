# Extra tooling — proposed expansions

The current toolkit (semgrep, bandit, gosec, cppcheck, clang-tidy,
flawfinder, regexploit, trufflehog, gitleaks, trivy, osv-scanner,
njsscan, checkov) gets us a combined **~57%** recall on
DVWA + NodeGoat + Django.nV. Below are ranked candidates for raising
that further, organised by what they buy us.

## 1. More language-specific SAST

| Tool | Language(s) | Bucket(s) it strengthens | Distribution |
|---|---|---|---|
| **brakeman** | Ruby on Rails | injection, mass-assignment, CSRF, deser | gem |
| **find-sec-bugs** (SpotBugs plugin) | JVM (Java/Kotlin/Scala) | injection, crypto, deser, auth | jar |
| **psalm + plugin-security-analysis** | PHP | injection, crypto, taint | composer |
| **eslint + eslint-plugin-security + security-node** | JS/TS | injection, crypto, regex DoS | npm |
| **rubocop + rubocop-thread_safety** | Ruby | concurrency / race | gem |
| **detekt + detekt-rules-libraries** | Kotlin | misuse, deser, XSS in Spring | jar |

ROI: high for JVM/Ruby coverage which we have nothing on; medium for
PHP/JS (we already have semgrep PHP/JS rules but specialists catch more).

## 2. Heavier polyglot SAST

| Tool | Why it'd help | Constraint |
|---|---|---|
| **CodeQL CLI** | Genuinely strong cross-file taint, especially for IDOR / auth-bypass classes that semgrep struggles with. Wide language support. | Custom license, free for OSS scanning; not redistributable in our image without checking. |
| **Snyk Code (CLI)** | Good auth/access detection. | Closed source, requires API key. |
| **Insider** | OSS, polyglot. | Project quiet recently; verify maintenance. |

Recommendation: skip closed-source; investigate adding **CodeQL** as an
opt-in step (`scan.sh --codeql`) where the user provides queries.
That's significant integration work — file under "later".

## 3. SCA depth

We have `trivy fs` and `osv-scanner`. Adjacent:

| Tool | What it adds |
|---|---|
| **dependency-check** (OWASP) | Slow but well-curated, including legacy Java/.NET; complements OSV which leans modern. |
| **retire.js** | JS-specific stale-libs detector, catches CDN-loaded `<script src="…jquery-1.11.0.js">` patterns OSV misses. |
| **govulncheck** | Go module vulns with reachability analysis (only flags vulns whose code paths are actually reachable). |
| **cargo-audit** / **pip-audit** | Lang-specific, often quicker first signal than OSV. |

ROI: govulncheck is **highest** — reachability analysis is what most
SCA tools lack and dramatically reduces noise. retire.js is a quick
win for JS-heavy repos.

## 4. Dataflow / fuzz-adjacent

| Tool | Why |
|---|---|
| **AFL++ / libFuzzer harnesses** | Out of scope for static, but if the user has fuzz harnesses already we could surface coverage gaps. |
| **CrabbyJS** / **wonk** | Experimental JS taint / dataflow tools; not reliable enough yet. |
| **gosec --include-rules-with-cve** | Tighter Go signal. |

## 5. IaC / k8s / cloud

We have `trivy fs` IaC and `checkov`. Possible additions:

| Tool | What |
|---|---|
| **tfsec** | Terraform-only; somewhat redundant with checkov but catches different things in AWS/Azure modules. |
| **kube-linter** | k8s-only; complements checkov's k8s rules. |
| **prowler** | Cloud account scanner — out of scope (runtime against AWS/Azure/GCP). |
| **kics** | Polyglot IaC; redundant with checkov. |

ROI: tfsec is **cheap to add** and its findings overlap-and-extend
checkov, with low FP rate.

## 6. Container image / Dockerfile

Adjacent to filesystem scanning:

| Tool | What |
|---|---|
| **dockle** | Dockerfile/image best-practices linter (CIS-aligned). |
| **hadolint** | Dockerfile linter. |
| **grype** | Image vuln scanner; redundant with `trivy image` — skip. |

ROI: hadolint is a one-liner, useful when scanning a repo with a
`Dockerfile`.

## 7. Custom semgrep rule expansions

The biggest single recall lever, IME. Targeted families to write:

- **PHP**: bypassable XSS filters (`preg_replace("/<.*script.*/", "", $X)`),
  `include $_GET[$K];`, `mysqli_query($conn, $X)` where `$X` lacks
  `prepare`, `unserialize($_GET[…])`.
- **Python (Django/Flask)**: `cursor.execute("… %s" % …)`, `mark_safe`
  on user input, `pickle.loads` on requests, `eval`/`exec` of request
  body.
- **Node.js**: `eval(req.body…)`, `child_process.exec(req.…)`,
  `redirect(req.query…)` without allow-list, prototype-pollution
  patterns (`Object.assign(target, req.body)`).
- **Java**: `Runtime.exec`, `ObjectInputStream.readObject`, JDBC string
  concat.
- **Go**: `template.HTML(…)` from request, `os/exec.CommandContext`
  with concatenated args, `crypto/md5` for hashing.

## 8. Auth / access-control specific

The hardest class for SAST. Heuristic rules can flag:

- Handlers that touch state-changing DB ops (UPDATE/INSERT/DELETE)
  without an upstream auth/role check function.
- Routes accepting an object id from request that don't filter by
  current-user/owner.
- Missing `@login_required` / `@PreAuthorize` decorators on handlers.

These are best implemented as semgrep rules per framework, not as a
separate tool.

## 9. Workflow/CI

| Tool | What |
|---|---|
| **actionlint** | GitHub Actions workflow linter — semgrep already covers most security cases via `p/github-actions`, but actionlint flags syntax/typing too. |
| **pinact** / **harden-runner** integration | Not a scanner per se, but useful adjuncts. |

## Suggested next adds (recommended order)

1. **govulncheck** — reachability-aware Go SCA. Tiny addition, big de-noise.
2. **brakeman** — Rails coverage we currently lack. One install, one parser.
3. **find-sec-bugs** — JVM coverage we lack. Slightly heavier but
   stable.
4. **retire.js** — JS-specific SCA for CDN-vendored libs.
5. **tfsec** + **hadolint** — cheap IaC/Docker bumps.
6. **Custom rule expansion** in `rules/` — the highest absolute-impact
   step but also the most ongoing work; each new rule must be
   recall-tested against the benchmarks.

## Out of scope (for now)

- DAST (zaproxy, nuclei) — we're a SAST tool.
- Fuzzing harness orchestration.
- Cloud account scanners (Prowler, ScoutSuite).
- Anything closed-source that requires API keys (Snyk, Veracode).
- AI-enriched triage — already covered in `docs/enrich-image.md`.
