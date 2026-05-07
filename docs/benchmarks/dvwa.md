# Benchmark: DVWA (digininja/DVWA)

DVWA is an intentionally-vulnerable PHP teaching app. Each module ships
four security tiers — `low.php`, `medium.php`, `high.php`,
`impossible.php` — and the first three are deliberately broken in
documented ways. We use that structure as a recall yardstick: we know
exactly which files *should* light up and which (`impossible.php`)
should stay dark.

## Ground truth

Each row is one *expected vulnerable file*. Static analysis won't catch
all of them (some are runtime-only — captcha bypass, brute force rate
limits, weak crypto-key entropy that depends on RNG seeding) — but the
ones marked **SAST-detectable** must register at least one finding.

| Module | low.php | medium.php | high.php | Class | CWE | SAST-detectable |
|---|---|---|---|---|---|---|
| `exec` | ✓ | ✓ | ✓ | command injection | CWE-78 | yes |
| `sqli` | ✓ | ✓ | ✓ | SQL injection | CWE-89 | yes |
| `sqli_blind` | ✓ | ✓ | ✓ | SQL injection (blind) | CWE-89 | yes |
| `xss_r` | ✓ | ✓ | ✓ | reflected XSS | CWE-79 | yes |
| `xss_s` | ✓ | ✓ | ✓ | stored XSS | CWE-79 | yes |
| `xss_d` | ✓ | ✓ | ✓ | DOM XSS | CWE-79 | yes (JS rules) |
| `fi` | ✓ | ✓ | ✓ | LFI/RFI | CWE-22, CWE-98 | yes |
| `upload` | ✓ | ✓ | ✓ | unrestricted upload | CWE-434 | yes |
| `csrf` | ✓ | ✓ | ✓ | missing CSRF token | CWE-352 | yes (heuristic) |
| `open_redirect` | ✓ | ✓ | ✓ | open redirect | CWE-601 | yes |
| `weak_id` | ✓ | ✓ | ✓ | weak session id | CWE-330, CWE-384 | yes (pattern) |
| `bac` | ✓ | ✓ | ✓ | broken access control | CWE-639, CWE-285 | partial |
| `authbypass` | ✓ | ✓ | ✓ | auth bypass | CWE-287 | partial |
| `api` | ✓ | ✓ | ✓ | API flaws (BOLA, mass-assignment, XXE) | various | partial |
| `cryptography` | ✓ | ✓ | ✓ | weak primitive / ECB / hardcoded key | CWE-327, CWE-798 | yes |
| `csp` | ✓ | ✓ | — | CSP misconfig / JSONP | CWE-79 | partial |
| `javascript` | client-side checks | client-side checks | obfuscated checks | trust-the-client | CWE-602 | partial |
| `brute` | weak (no rate limit) | weak | weak | rate limit / weak auth | CWE-307 | no (runtime) |
| `captcha` | bypassable | bypassable | bypassable | logic | — | no (runtime) |

**Total SAST-detectable expected vulnerable files**: 14 modules × 3
tiers = **42** files (excluding `impossible.php` and runtime-only).

Plus `impossible.php` files **must not** be flagged — used as a
false-positive check (precision yardstick).

## Current state — vuln-scan run on 2026-05-07

```
total findings: 44
by_tool:        {semgrep: 43, bandit: 1}
by_category:    {injection: 33, path_network: 9, secrets: 1, uncategorized: 1}
```

Recall by module:

| Module | low | medium | high | covered? |
|---|---|---|---|---|
| `exec` | ✓ | ✓ | ✓ | **fully** |
| `sqli` | ✓ | — | — | partial (low only) |
| `sqli_blind` | ✓ | ✓ | ✓ | full |
| `xss_r` | — | — | — | **missing** |
| `xss_s` | — | — | — | **missing** |
| `xss_d` | — | — | — | **missing** |
| `fi` | — | — | ✓ | partial (high only) |
| `upload` | — | — | — | **missing** |
| `csrf` | — | — | — | **missing** |
| `open_redirect` | — | — | — | **missing** |
| `weak_id` | — | — | — | **missing** |
| `bac` | ✓ | ✓ | — | partial |
| `authbypass` | — | — | — | **missing** |
| `api` | — | — | — | **missing** |
| `cryptography` | — | — | — | **missing** |

12 modules × 3 tiers = 36 expected detections; **6 covered, 30 missed**
on the per-file level. Recall: **17%**.

## Why the gaps

1. **No `p/xss` rule pack loaded.** The default config
   (`p/security-audit` + `p/owasp-top-ten` + `p/cwe-top-25`) is
   polyglot and shallow on PHP-specific XSS sinks. Adding `p/xss`
   should pick up `$_GET[…]` flowing into `$html` strings in
   xss_r/xss_s.

2. **DVWA's "build the string here, echo it elsewhere" pattern
   defeats single-file taint.** `source/low.php` builds `$html` and the
   sibling `index.php` echoes it via heredoc. Semgrep's OSS engine
   tracks taint within a function/file but rarely follows
   `include`/`require` boundaries, so XSS isn't joined up.
   *Mitigation*: add a heuristic rule that flags any string built from
   `$_GET[…]` / `$_POST[…]` without `htmlspecialchars` / `htmlentities`
   in the same file.

3. **No PHP-specific upload / CSRF / open-redirect rule pack.**
   `p/php` from the registry covers `move_uploaded_file` without
   extension/MIME check, missing CSRF tokens on state-changing POSTs,
   `header("Location: " . $_GET[…])`, and `setcookie` with weak
   session ids. Not currently loaded.

4. **No crypto/PHP rules for weak primitives.** `md5(`, `sha1(`,
   `mcrypt_*`, ECB mode usage need a `p/php-crypto` or
   `p/javascript-crypto` pack (semgrep has crypto rules under
   `p/security-audit` but they're language-shallow).

## Iteration plan

Each iteration: change rule packs / add custom rules / tune scan.sh,
re-run, record the recall delta in this file under "history".

### Iteration 1 — rule pack expansion (proposed)

Add to `scan.sh` semgrep invocation:
- `--config p/xss` — XSS sinks
- `--config p/php` — PHP-specific taint rules (uploads, redirects,
  weak crypto)
- `--config p/insecure-transport` — http-in-redirect, http URLs
- `--config p/jwt` — JWT alg=none etc. (no JWT in DVWA but cheap)

Hypothesis: recall jumps from ~17% to ~50%.

### Iteration 2 — custom DVWA-shaped rules

Some patterns evade off-the-shelf packs. Add `bench/dvwa-rules.yml`
with hand-written semgrep rules:
- `move_uploaded_file` without an `extension` / `pathinfo` / `MIME`
  guard nearby
- `header("Location: " . $tainted)` regardless of regex filter
- `setcookie(…, $sequential_int)` for weak session ids
- POST handlers that touch `mysqli_query` without a `csrf_token` /
  `checkToken` call upstream

### Iteration 3 — interfile XSS heuristic

Add a rule that flags taint *into* a string variable when the same file
defines no encoder, regardless of whether the echo is in this file —
catches DVWA's split-file pattern at the cost of more false positives.

### Iteration 4 — tracker for false positives

Verify `impossible.php` files stay clean; any finding there counts as
a false positive and gets a -1 against precision.

## How to re-measure

```sh
bench/dvwa.sh
```

The script clones DVWA at a pinned commit, runs `scan.sh` (with the
current rule-pack config), and emits:
- `bench/results/dvwa-<timestamp>.md` — per-module recall table
- a one-line console summary suitable for a CI assertion

## History

| Date | Recall | FPs in impossible.php | Notes |
|------|--------|------------------------|-------|
| 2026-05-07 | 17% (6/36)  | 0 | baseline, default rule packs (`p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`) |
| 2026-05-07 | 22% (8/36)  | 1 | iter 1: added `p/xss`, `p/php`, `p/insecure-transport`, `p/jwt` |
| 2026-05-07 | 52% (19/36) | 3 | iter 2: added 5 hand-written rules in `rules/php-web.yml` (XSS string-concat, unrestricted upload, open redirect, weak session id, weak hash). `upload`/`csrf`/`open_redirect` all 3 tiers; XSS partial; weak_id partial |

### Remaining gaps after iter 2

- **`xss_s` / `xss_d` / `xss_r medium-high`** — DVWA's filters (`preg_replace("/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i", "")` etc.) bypass our string-concat rule because the tainted variable is sanitised in-place. Need a rule that matches the *bypassable* filter pattern itself.
- **`cryptography`** — DVWA's `md5( $pass_new )` *does* match our pattern but the variable name `$pass_new` doesn't equal our `$_POST[...]` patterns. Need a broader rule for "md5/sha1 of a variable that traces back to user input or to a password column".
- **`fi medium-low`** — file inclusion via `include $_GET[$K]`. Add a direct rule.
- **`sqli medium-high`** — DVWA wraps in `mysqli_real_escape_string` which the registry rule treats as a sanitiser, but the column is unquoted in some places. Custom rule needed.

### Iter 3 candidates

1. Match `md5($X)` / `sha1($X)` *without* requiring `$X` to be `$_GET[…]` — flag any md5/sha1 in a file that imports / uses `password` / `token` / `auth` keywords.
2. Match weak XSS filter: `preg_replace(/<.*script.*/i, "", $X)` — the bypass pattern.
3. Match `include $X;` / `require $X;` where `$X` is `$_GET[…]` directly.
4. Triage the 3 `impossible.php` false positives — likely overly-broad upload rule, since `move_uploaded_file` is called even in the secure version with strict guards.
