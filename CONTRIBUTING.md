# Developer Guide

## Quick Start

**Just commit your code.** The pre-commit hook runs all CI checks automatically. If the commit succeeds, CI will pass.

## Setup

Install the pre-commit hook (one-time setup):

```powershell
git config core.hooksPath .githooks
```

Install development dependencies:

```powershell
pip install -r requirements-dev.txt
```

## Your Workflow

1. Write code
2. Commit: `git commit -m "Your message"`
   - Hook runs automatically (5-10 seconds)
   - Commit succeeds = CI will pass
   - Commit blocked = Fix the issue shown
3. Push: `git push`

## Manual CI Check

Run all CI checks without committing:

```powershell
ruff check .
ruff format --check .
mypy *.py
```

## Quick Fixes

If the hook fails:

**Lint/Format issues:**
```powershell
ruff check --fix .
ruff format .
git add -u
git commit
```

**Type errors:** Fix manually (mypy shows line numbers)

## What Gets Checked

| Check | Command | Why |
|-------|---------|-----|
| Lint | `ruff check .` | Code quality |
| Format | `ruff format --check .` | Consistent style |
| Types | `mypy *.py` | Type safety |

## Bypassing the Hook

```bash
git commit --no-verify  # Not recommended - CI will fail
```
