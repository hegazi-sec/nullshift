# Contributing to NullShift

First — **thank you** for taking the time to look at this. NullShift is an open project. Whether you're reporting a bug, suggesting a feature, fixing a typo, or adding a whole new SIEM connector, your contribution is genuinely welcome.

## Ways to Contribute

- 🐛 **Report bugs** — open an [issue](https://github.com/hegazi-sec/nullshift/issues) with reproduction steps. The more detail, the faster the fix.
- 💡 **Suggest features** — open an issue with the use case and the problem you're trying to solve.
- 🔧 **Submit a pull request** — fix a bug, add a feature, improve docs, or write a test.
- 📚 **Improve the knowledge base** — add or refine markdown playbooks in `data/kb/` for new threat scenarios.
- 🔌 **Build a new SIEM connector** — extend the `SIEMConnector` base class in `app/connectors/`.
- 🌍 **Translate the UI** — i18n PRs are very welcome.

## Branching Strategy

NullShift uses a simple two-branch flow:

| Branch | Purpose |
|---|---|
| `main` | Stable, release-tagged versions. **Do not target PRs here directly.** |
| `beta` | Active development. **All PRs target this branch.** |

When `beta` is stable and well-tested, it gets merged into `main` and a new release is tagged.

## Development Setup

```bash
git clone https://github.com/hegazi-sec/nullshift.git
cd nullshift
git checkout beta
python setup.py        # creates the venv, installs deps, registers the CLI
```

In a second terminal, stream logs while you work:

```bash
nullshift logs
```

Edit code. Save. Uvicorn's `--reload` flag picks up changes within a second.

## Pull Request Checklist

Before opening a PR, please make sure:

- [ ] Your PR targets the **`beta`** branch, not `main`.
- [ ] The PR description explains the **why**, not just the **what**.
- [ ] Code changes are **scoped** — no unrelated refactors mixed in.
- [ ] Tests pass: `pytest tests/`
- [ ] For UI changes, include a **before / after screenshot**.
- [ ] No secrets, `.env` files, or generated databases (`.db`, `chroma/`) committed.
- [ ] Commit messages follow the project style (see below).

## Code Style

### Python

- Follow **PEP 8** spacing and naming.
- Add **type hints** to new public functions and methods.
- **Docstrings** should explain the *why*, not restate the signature.
- Prefer **early returns** over deep nesting.
- Avoid adding dependencies unless they're significantly easier than rolling it yourself.

### Frontend

- Vanilla **HTML + JS + CSS**. No build step, no framework.
- Keep styles and scripts **inline** in each HTML file — that's intentional, it keeps the install footprint tiny.

### General

- **Don't add backwards-compatibility shims** for code that hasn't shipped yet.
- **Don't add comments** that just restate the code. Add comments for *why* something is unusual or non-obvious.
- **Don't add error handling** for situations that can't happen — trust the framework / internal callers.

## Commit Messages

- **Short subject line** (≤72 chars), **imperative mood** ("Fix RAG validation race", not "Fixed" or "Fixes").
- **Body** (optional) — explain context and reasoning when needed, separated by a blank line.

### Example

```
Fix RAG validation: only run when sync_state is complete or skipped

The validation pass was firing during indexing, causing race conditions
where the retry call hit an empty collection. Now gated on the same
status check the Admin UI uses.
```

## Reporting Bugs

Use the issue template when available. At minimum, please include:

- **OS** (Mac / Linux / Windows + version)
- **Python version** (`python3 --version`)
- **LLM provider** in use (Claude Agent SDK / Anthropic / OpenAI / Ollama / etc.)
- **SIEM provider** in use (Wazuh / LimaCharlie / Splunk / Elastic / Sentinel / none)
- **What you did** — steps to reproduce
- **What you expected**
- **What actually happened** — include the relevant lines from `nullshift logs`
- **Screenshots** if it's a UI issue

## Security Vulnerabilities

**Do not open public issues for security bugs.** Instead, email the maintainer privately or use GitHub's private vulnerability reporting feature on the repo. You'll get an acknowledgement within 48 hours.

## Code of Conduct

Be kind. Be technical. Disagree with ideas, not people. Bad-faith arguments, harassment, or hostility have no place here and will be moderated.

## Questions?

Open a [discussion](https://github.com/hegazi-sec/nullshift/discussions) or an issue — no question is too small. Whether you're stuck on setup, exploring the codebase, or just curious about a design choice, please ask. I'm always happy to help.

— Ahmed Hegazi
