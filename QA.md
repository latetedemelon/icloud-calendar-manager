# QA / Verification

This project is verified by CI (Python 3.9–3.12 matrix) on every push and pull
request, and can be checked locally with the steps below.

## How to run the QA suite locally

```bash
pip install -e ".[dev]"

# 1. Unit tests (fully mocked; no network required)
pytest

# 2. Lint — build-blocking gate (syntax errors / undefined names)
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

# 3. Lint — full style (non-blocking in CI)
flake8 . --count --max-complexity=10 --max-line-length=127 --statistics

# 4. Build the distribution
python -m build        # produces dist/*.whl and dist/*.tar.gz

# 5. CLI smoke test
icloud-calendar --version
icloud-calendar check  # without creds: prints a config error and exits 2
```

The integration test (`tests/test_integration.py`) is skipped unless you opt in
with `ICLOUD_INTEGRATION=1` and real `APPLE_ID` / `APPLE_PASSWORD`; it is
read-only and never mutates the account.

## Latest verification snapshot

- **Date:** 2026-05-29
- **Commit:** `6ce6bbe` (branch `main`)
- **Version:** 0.3.0
- **Local interpreter:** CPython 3.11; **CI matrix:** 3.9, 3.10, 3.11, 3.12

| Check | Result |
| :--- | :--- |
| `pytest` | 64 passed, 1 skipped (opt-in integration) |
| `flake8` critical (`E9,F63,F7,F82`) | clean (0) |
| `flake8` full (complexity ≤ 10, line ≤ 127) | clean (0) |
| `python -m build` | wheel + sdist built (0.3.0); `py.typed` + `LICENSE` bundled |
| CLI `--version` | prints `icloud-calendar 0.3.0` |
| CLI `check` without credentials | friendly `Configuration error`, exit code 2 |

## Branch / merge status at snapshot

All historical branches are merged into `main` (each reports 0 commits not in
`main`); no open pull requests:

- `patch-1` — merged (PR #1)
- `Reminders` — merged (PR #1)
- `claude/jolly-gates-k3jk5` — merged (PRs #2, #3)
