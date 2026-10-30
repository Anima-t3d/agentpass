"""HTML to plain text for the email preview (docs/APPROVAL-PREVIEWS.md section 4.1).

A whitelist converter: every tag is dropped, ``script``, ``style``, ``head`` and
``template`` content with it, comments are ignored. ``<a href>`` becomes ``text [url]``.
The HTML itself is never rendered anywhere.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

MAX_HTML_CHARS = 400_000  # input cap; the rest is not parsed
_SKIP = {"script", "style", "head", "template", "noscript"}
_BLOCK = {
    "p", "div", "br", "li", "ul", "ol", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "pre", "hr", "section", "article", "header", "footer",
}  # fmt: skip
_BLANK_RUNS = re.compile(r"\n{3,}")


class _Converter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []  # text with "[url]" after each link
        self.bare: list[str] = []  # the same text without the URLs, for comparison
        self.links: list[tuple[str, str]] = []  # (link text, href)
        self._skip = 0
        self._href: str | None = None
        self._link_text: list[str] = []

    def _both(self, text: str) -> None:
        self.parts.append(text)
        self.bare.append(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP:
            self._skip += 1
        elif self._skip:
            return
        if tag in _BLOCK:
            self._both("\n")
        if tag == "a":
            self._href = next((v for k, v in attrs if k == "href" and v), None)
            self._link_text = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK and not self._skip:
            self._both("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag in _BLOCK:
            self._both("\n")
        if tag == "a" and self._href is not None:
            shown = "".join(self._link_text).strip()
            self.links.append((shown, self._href.strip()))
            self.parts.append(f" [{self._href.strip()}]")
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self._both(data)
        if self._href is not None:
            self._link_text.append(data)


def _tidy(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.split("\n")]
    return _BLANK_RUNS.sub("\n\n", "\n".join(lines)).strip()


def html_to_text(html: str) -> tuple[str, str, list[tuple[str, str]]]:
    """``(text with link URLs, text without them, [(link text, href)])``."""
    parser = _Converter()
    try:
        parser.feed(html[:MAX_HTML_CHARS])
        parser.close()
    except Exception:  # malformed markup must not stop the preview; keep what was read
        pass
    return _tidy("".join(parser.parts)), _tidy("".join(parser.bare)), parser.links
