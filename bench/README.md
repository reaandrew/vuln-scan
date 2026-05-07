# bench/

Recall benchmarks for `vuln-scan`. **Not part of the scanner** — these
scripts clone known-vulnerable third-party apps, run `scan.sh` against
them, and compare findings to a hand-curated ground-truth list. They
exist purely to detect regressions and drive rule iteration.

The Docker image excludes this directory (`.dockerignore`), so
`docker pull ghcr.io/reaandrew/vuln-scan:latest` does not ship the
benchmark targets, ground-truth tables, or runners.

## Targets

| Script | Target | Language(s) |
|---|---|---|
| `dvwa.sh`     | [digininja/DVWA](https://github.com/digininja/DVWA) | PHP |
| `nodegoat.sh` | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | Node.js |
| `django.sh`   | [nVisium/django.nV](https://github.com/nVisium/django.nV) | Python / Django |

Each script:

1. clones the target,
2. runs `../scan.sh`,
3. emits a per-module recall table to `bench/results/<target>-<ts>/recall.md`,
4. prints a one-line summary suitable for a CI assertion.

Ground-truth tables live next to each runner:
`docs/benchmarks/<target>.md`.

## Running

```sh
bench/dvwa.sh        # one target
bench/nodegoat.sh
bench/django.sh

bench/all.sh         # all targets, prints a combined recall summary
```

The runners share helpers in `bench/lib.sh`. To add a new benchmark:

1. Curate `docs/benchmarks/<name>.md` with the ground-truth file list +
   expected CWE per file.
2. Copy one of the existing scripts and edit the constants at the top.
3. Add an entry to `bench/all.sh`.

## What "recall" means here

For each `(file, expected-CWE)` row in the ground-truth table we ask:
did `scan.sh` produce *any* finding on that file? We don't require the
finding to map to the exact CWE we expected — only that the file
isn't silently passing through.

Files marked **safe-by-design** (DVWA's `impossible.php`, NodeGoat's
`/contributors` patched routes, etc.) are flipped: any finding there
counts as a false positive and is reported separately.

The ground-truth tables are *deliberately conservative* — we only list
flaws a static analyser could plausibly catch. Runtime-only issues
(brute-force without rate limiting, captcha bypass) are noted but
excluded from the recall denominator.
