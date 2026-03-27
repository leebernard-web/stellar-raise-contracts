# GitHub Actions Test Workflow — Script Reference

## Overview

`github_actions_test.sh` validates the GitHub Actions workflow files in this
repository. It enforces correctness, speed, and security rules that keep CI
fast and reliable. The companion test file `github_actions_test.test.sh`
exercises every check against both the real repository and synthetic fixtures.

---

## Scripts

| Script | Purpose |
|---|---|
| `scripts/github_actions_test.sh` | Validates workflow files (12 checks) |
| `scripts/github_actions_test.test.sh` | Tests the validator (20 tests, edge cases included) |

Run locally from the repository root:

```bash
bash scripts/github_actions_test.sh
bash scripts/github_actions_test.test.sh
```

Set `VERBOSE=1` to see full output from the validator during tests:

```bash
VERBOSE=1 bash scripts/github_actions_test.test.sh
```

---

## Checks performed

### Check 1 — Required workflow files exist and are non-empty

Verifies that `rust_ci.yml`, `testnet_smoke.yml`, and `spellcheck.yml` all
exist under `.github/workflows/` and contain at least one byte. Missing or
empty files silently disable CI jobs.

### Check 2 — No workflow references `actions/checkout@v6`

`actions/checkout@v6` does not exist. Any workflow referencing it fails
immediately at the checkout step. The current stable release is `v4`.

### Check 3 — No duplicate WASM build step in `rust_ci.yml`

Building the WASM binary twice in the same job compiles identical artifacts
and wastes 60–90 seconds of CI time per run. A single scoped build
(`-p crowdfund`) is sufficient.

### Check 4 — Smoke test does not call non-existent contract functions

The functions `is_initialized` and `get_campaign_info` are not part of the
crowdfund contract's public ABI. Calling them causes the smoke test to fail
with a confusing on-chain error.

### Check 5 — Smoke test `initialize` call includes `--admin`

The crowdfund contract's `initialize` entry point requires an `--admin`
argument. Omitting it causes the transaction to be rejected on-chain.

### Check 6 — Smoke test WASM build is scoped to `-p crowdfund`

Building the entire workspace compiles every crate unnecessarily. Scoping to
`-p crowdfund` is 2–4x faster and avoids compiling crates that may not
support the `wasm32` target.

### Check 7 — Smoke test uses `stellar-cli`, not deprecated `soroban-cli`

The Soroban CLI was renamed to the Stellar CLI. The old `soroban-cli` package
is unmaintained and may contain unpatched vulnerabilities.

### Check 8 — `rust_ci.yml` includes a `frontend` job

Without a dedicated frontend job, Jest tests never run in CI. The frontend
job runs in parallel with the Rust job, adding zero wall-clock time to the
pipeline.

### Check 9 — `rust_ci.yml` uses `Swatinem/rust-cache`

Without caching, every CI run re-downloads and recompiles all Rust
dependencies from scratch. `Swatinem/rust-cache` caches `~/.cargo` and
`target/` between runs, reducing cold-build time by 60–80%.

### Check 10 — `rust_ci.yml` has `timeout-minutes`

Without a timeout, a hung build can consume a GitHub Actions runner for up to
6 hours, blocking other PRs and wasting CI minutes. A 30-minute cap is
recommended for the main job.

| Script | Purpose |
|---|---|
| `scripts/github_actions_test.sh` | Validates workflow files in CI or locally (12 checks) |
| `scripts/github_actions_test.test.sh` | Tests the validator against pass/fail scenarios (13 tests) |

The smoke test only needs to read source code. Explicit
`permissions: contents: read` prevents a compromised job from pushing commits
or modifying releases.

### Check 12 — `rust_ci.yml` includes a `wasm-opt` optimisation step

The raw WASM binary from rustc is not size-optimised. Running `wasm-opt -Oz`
reduces binary size by 20–40%, lowering Stellar deployment costs and speeding
up contract uploads.

---

## Speed optimisations in `rust_ci.yml`

| What | Where | Value |
|---|---|---|
| Job hard timeout | `jobs.check.timeout-minutes` | 30 min |
| WASM build step timeout | `Build crowdfund WASM for tests` step | 10 min |
| Test step timeout | `Run tests including property-based tests` step | 15 min |
| Elapsed-time log | `Log total job elapsed time` step (always runs) | soft warn at 20 min |

---

The validator (`github_actions_test.sh`) enforces all four bounds with dedicated
checks (checks 8–12). Any workflow that removes a timeout or the elapsed-time
step will fail CI immediately.

## Security notes

- The validator reads workflow files only — it never writes or executes them.
- No secrets or credentials are accessed by the validator.
- `set -euo pipefail` ensures unset variables and pipeline errors are fatal.
- All `grep` calls use `--` to prevent flag injection from filenames.
- `actions/checkout@v4` is the current stable, audited release.
- Using `stellar-cli` (the maintained successor) reduces supply-chain risk
  compared to the deprecated `soroban-cli` package.
- `timeout-minutes` bounds prevent a compromised or infinite-looping
  dependency from holding a runner indefinitely.
- `permissions: contents: read` enforces least-privilege on the smoke test job.
- The spellcheck action runs with default read-only permissions.

---

## Test coverage

The test suite (`github_actions_test.test.sh`) covers 20 tests across 12 checks:

| Test | Scenario |
|---|---|
| 1 | Real repository passes all 12 checks (happy path) |
| 2 | `spellcheck.yml` is missing |
| 3 | Workflow file exists but is empty (zero bytes) |
| 4 | Workflow file contains only whitespace (documents current behaviour) |
| 5 | `checkout@v6` typo in `rust_ci.yml` |
| 6 | `checkout@v6` typo in `testnet_smoke.yml` |
| 7 | Duplicate WASM build steps in `rust_ci.yml` |
| 8 | Smoke test calls non-existent `is_initialized` |
| 9 | Smoke test calls non-existent `get_campaign_info` |
| 10 | Smoke test `initialize` missing `--admin` |
| 11 | Smoke test WASM build missing `-p crowdfund` |
| 12 | Smoke test uses deprecated `soroban-cli` |
| 13 | `rust_ci.yml` missing `frontend` job |
| 14 | `rust_ci.yml` missing `Swatinem/rust-cache` |
| 15 | `rust_ci.yml` missing `timeout-minutes` |
| 16 | `testnet_smoke.yml` missing least-privilege permissions |
| 17 | `rust_ci.yml` missing `wasm-opt` step |
| 18 | `rust_ci.yml` missing entirely |
| 19 | `testnet_smoke.yml` missing entirely |
| 20 | Multiple simultaneous failures are all reported (no short-circuit) |

---

## What was changed in this branch

| File | Change |
|---|---|
| `scripts/github_actions_test.sh` | Added checks 9–12 (rust-cache, timeout, permissions, wasm-opt); extracted `check_file_exists_and_nonempty` helper; added `readonly` to constants; improved `grep` safety with `--` flag; updated summary to show 12/12 |
| `scripts/github_actions_test.test.sh` | Added tests 14–20 covering new checks 9–12 and additional edge cases; added `VERBOSE` env var support; improved fixture isolation |
| `scripts/github_actions_test.md` | Documented all 12 checks, 20 tests, VERBOSE flag, and security rationale for new checks |
