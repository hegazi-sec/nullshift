"""The four app pages follow the Content-Security-Policy page rules.

Under `script-src 'self' 'nonce-…'` an inline handler, a javascript: URL or a
string timer does not raise an error: the button just stops working. This
reads the page files directly, so nothing here starts the app.
"""
import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"
PAGES = ["ui.html", "admin.html", "setup.html", "login.html"]

FORBIDDEN = {
    # on*= attributes, also inside JS template strings and innerHTML
    "inline handler": re.compile(r"""(?<![.\w$-])on[a-z]{3,}\s*=\s*["'`\\]"""),
    "javascript: URL": re.compile(r"javascript:", re.I),
    "string timer": re.compile(r"""\bset(?:Timeout|Interval)\(\s*["'`]"""),
    "eval": re.compile(r"\beval\s*\(|\bnew\s+Function\b"),
    "setAttribute('on…')": re.compile(r"""setAttribute\(\s*["'`]on""", re.I),
}


@pytest.mark.parametrize("page", PAGES)
def test_page_has_no_inline_script(page):
    src = (APP / page).read_text(encoding="utf-8")
    for what, pattern in FORBIDDEN.items():
        m = pattern.search(src)
        line = src.count("\n", 0, m.start()) + 1 if m else 0
        assert not m, f"{page}:{line}: {what} {m.group(0)!r} is blocked by the CSP"


@pytest.mark.parametrize("page", PAGES)
def test_page_has_one_script_tag(page):
    # html_page stamps the nonce on every <script; one inline block, no external src
    src = (APP / page).read_text(encoding="utf-8")
    tags = re.findall(r"<script\b[^>]*>", src, flags=re.I)
    assert len(tags) == 1, f"{page}: {len(tags)} script tags"
    assert "src=" not in tags[0]
