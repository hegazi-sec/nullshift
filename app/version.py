"""The NullShift version. A release bumps it (and pyproject.toml) in the commit its
signed tag `vMAJOR.MINOR.PATCH` points to; app/updater.py compares it with the release tags
to tell whether a newer release exists (docs/UPDATES.md)."""

VERSION = "0.4.0"
