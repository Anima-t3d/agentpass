"""Guards for the static landing page in ``site/``.

Stdlib only: the page has no build step, so these tests read the files as
they will be served and check structure, privacy, links, contrast, motion
and the "Coming soon" labelling of features not on ``main`` yet.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"

REPO_URL = "https://github.com/Anima-t3d/agentpass"
UPSTREAM_URL = "https://github.com/TorbenWetter/agentpass"

SECTION_IDS = [
    "hero",
    "is-this-you",
    "pain-blocked",
    "pain-blind",
    "pain-bitten",
    "pain-burned",
    "github",
    "how",
    "features",
    "security",
    "quickstart",
    "fit",
    "open-source",
    "faq",
    "footer",
]
DENYLIST = [
    "ts.net",
    "gmail.com",
    "claude.ai/code",
    "Generated with Claude",
    "Claude-Session",
]
UNRELEASED_TERMS = ["pwa", "push notification", "gh_mirror_fetch", "git mirror"]

HEADLINE = "Let your AI agents act. Keep the keys."
SUBHEAD = (
    "A self-hosted gateway that holds your credentials, asks you before anything "
    "risky, and shows you exactly what you're approving."
)

VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "source",
    "track",
    "wbr",
}


# --- helpers ---------------------------------------------------------------


def load_html() -> str:
    return (SITE / "index.html").read_text(encoding="utf-8")


def load_css() -> str:
    return (SITE / "assets" / "style.css").read_text(encoding="utf-8")


def load_js() -> str:
    return (SITE / "assets" / "main.js").read_text(encoding="utf-8")


def norm(text: str) -> str:
    return " ".join(text.split())


class Element:
    def __init__(self, tag: str, attrs: dict[str, str], in_soon: bool) -> None:
        self.tag = tag
        self.attrs = attrs
        self.in_soon = in_soon
        self.parts: list[str] = []

    @property
    def text(self) -> str:
        return norm("".join(self.parts))

    @property
    def classes(self) -> set[str]:
        return set(self.attrs.get("class", "").split())


class Page(HTMLParser):
    """Collects every element (document order), its text and whether it sits in ``.soon``."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[Element] = []
        self.stack: list[Element] = []
        self.texts: list[tuple[str, bool]] = []  # (data, inside .soon)

    def _open(self, tag: str, attrs: list[tuple[str, str | None]]) -> Element:
        a = {k: (v or "") for k, v in attrs}
        in_soon = (
            any("soon" in e.classes for e in self.stack) or "soon" in a.get("class", "").split()
        )
        el = Element(tag, a, in_soon)
        self.elements.append(el)
        return el

    def handle_starttag(self, tag, attrs):
        el = self._open(tag, attrs)
        if tag not in VOID:
            self.stack.append(el)

    def handle_startendtag(self, tag, attrs):
        self._open(tag, attrs)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if any(e.tag in ("script", "style") for e in self.stack):
            return
        for e in self.stack:
            e.parts.append(data)
        self.texts.append((data, any("soon" in e.classes for e in self.stack)))

    def by_id(self, ident: str) -> Element | None:
        return next((e for e in self.elements if e.attrs.get("id") == ident), None)

    def ids(self) -> list[str]:
        return [e.attrs["id"] for e in self.elements if "id" in e.attrs]


def parse() -> Page:
    page = Page()
    page.feed(load_html())
    page.close()
    return page


def css_rules(css: str) -> list[tuple[str, str]]:
    """(selector, body) for every innermost rule, media blocks included."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css)]


def css_block(css: str, header: str) -> str:
    """Body of the first ``header { ... }`` block (brace matched), or ''."""
    m = re.search(header + r"\s*\{", css)
    if not m:
        return ""
    depth, i = 1, m.end()
    while depth and i < len(css):
        depth += {"{": 1, "}": -1}.get(css[i], 0)
        i += 1
    return css[m.end() : i - 1]


def decls(body: str) -> dict[str, str]:
    out = {}
    for part in body.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    chans = []
    for i in (0, 2, 4):
        c = int(h[i : i + 2], 16) / 255
        chans.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = chans
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def is_relative(url: str) -> bool:
    return not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", url.strip(), re.I) or url.startswith("data:")


# --- tests -----------------------------------------------------------------


def test_sections_present_in_order():
    ids = [i for i in parse().ids() if i in SECTION_IDS]
    assert ids == [i for i in SECTION_IDS if i in ids]


def test_no_third_party_resources():
    page = parse()
    for el in page.elements:
        assert el.tag != "iframe", "no embeds"
        for attr in ("src", "srcset", "poster"):
            if attr in el.attrs:
                assert is_relative(el.attrs[attr]), f"<{el.tag} {attr}={el.attrs[attr]}>"
        if el.tag == "link":
            assert is_relative(el.attrs.get("href", "")), f"<link href={el.attrs.get('href')}>"
    for url in re.findall(r"url\(\s*['\"]?([^'\")]+)", load_css()):
        assert is_relative(url), url
    assert "@import" not in load_css()
    assert not re.search(r"\bfetch\(|XMLHttpRequest|sendBeacon|import\(", load_js())


def test_no_private_strings():
    for path in SITE.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            for term in DENYLIST:
                assert term.lower() not in text, f"{term!r} in {path.relative_to(ROOT)}"


def test_internal_anchors_resolve():
    page = parse()
    ids = set(page.ids())
    for el in page.elements:
        href = el.attrs.get("href", "")
        if href.startswith("#") and href != "#":
            # Until every section exists (Task 3), a link may point at a planned section id.
            assert href[1:] in ids or href[1:] in SECTION_IDS, href


def test_repo_links_use_one_base():
    for url in re.findall(r"https?://(?:www\.)?github\.com/[^\s\"'<>)]*", load_html()):
        if url == UPSTREAM_URL:
            continue
        rest = url[len(REPO_URL) :]
        assert url.startswith(REPO_URL) and (rest == "" or rest[0] in "/#?"), url


def test_images_and_svgs_have_text_alternative():
    for el in parse().elements:
        if el.tag == "img":
            assert "alt" in el.attrs
        if el.tag == "svg":
            labelled = el.attrs.get("role") == "img" and el.attrs.get("aria-label")
            assert labelled or el.attrs.get("aria-hidden") == "true", el.attrs


def test_content_visible_without_js():
    for selector, body in css_rules(load_css()):
        d = decls(body)
        hides = d.get("opacity") == "0" or d.get("visibility") == "hidden"
        if hides and ".reveal" in selector:
            for sel in selector.split(","):
                assert sel.strip().startswith("html.js"), selector
    assert "classList.add('js')" in load_js() or 'classList.add("js")' in load_js()


def test_reduced_motion_disables_animation():
    block = css_block(load_css(), r"@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)")
    assert block, "no reduced-motion media block"
    assert re.search(r"animation(?:-duration)?\s*:\s*(?:none|0)", block)
    assert re.search(r"transition(?:-duration)?\s*:\s*(?:none|0)", block)
    assert "prefers-reduced-motion" in load_js()


def _theme_tokens(block: str) -> dict[str, str]:
    root = css_block(block, r":root") if ":root" in block else block
    return {
        k: v
        for k, v in decls(root).items()
        if k.startswith("--") and re.fullmatch(r"#[0-9a-fA-F]{3,6}", v)
    }


def test_contrast_both_themes():
    css = re.sub(r"/\*.*?\*/", "", load_css(), flags=re.S)
    dark = _theme_tokens(css_block(css, r"(?<![\w-]):root"))
    light = _theme_tokens(css_block(css, r"@media\s*\(\s*prefers-color-scheme:\s*light\s*\)"))
    for name, t in (("dark", dark), ("light", light)):
        for key in ("--bg", "--surface", "--text", "--muted", "--accent", "--accent-text"):
            assert key in t, f"{name}: {key} missing or not hex"
        assert contrast(t["--text"], t["--bg"]) >= 4.5, name
        assert contrast(t["--muted"], t["--bg"]) >= 4.5, name
        assert contrast(t["--muted"], t["--surface"]) >= 4.5, name
        assert contrast(t["--text"], t["--surface"]) >= 4.5, name
        assert contrast(t["--accent"], t["--bg"]) >= 3.0, name
        assert contrast(t["--accent-text"], t["--accent"]) >= 4.5, name


def test_keyboard_basics():
    page = parse()
    focusable = [e for e in page.elements if e.tag in ("a", "button", "summary", "input")]
    assert focusable and focusable[0].tag == "a" and focusable[0].attrs.get("href") == "#main"
    main = page.by_id("main")
    assert main is not None and main.tag == "main"
    assert any(":focus-visible" in sel and "outline" in body for sel, body in css_rules(load_css()))


def test_phone_width_rules():
    rules = css_rules(load_css())
    assert any(
        re.search(r"(^|[\s,])pre($|[\s,:])", sel) and decls(b).get("overflow-x") == "auto"
        for sel, b in rules
    )
    for tag in ("svg", "img"):
        assert any(
            re.search(rf"(^|[\s,]){tag}($|[\s,])", sel) and decls(b).get("max-width") == "100%"
            for sel, b in rules
        ), tag
    for sel, body in rules:
        if re.fullmatch(r"(html|body)(\s*,\s*(html|body))?", sel):
            for key in ("width", "min-width"):
                m = re.match(r"(\d+)px", decls(body).get(key, ""))
                assert not (m and int(m.group(1)) > 360), (sel, key)


def test_soon_elements_say_so():
    for el in parse().elements:
        if "soon" in el.classes:
            assert "Coming soon" in el.text, el.text[:80]


def test_unreleased_terms_only_inside_soon():
    for data, in_soon in parse().texts:
        low = data.lower()
        for term in UNRELEASED_TERMS:
            if re.search(rf"\b{re.escape(term)}", low):
                assert in_soon, f"{term!r} outside .soon: {data.strip()[:80]}"


def test_hero_copy():
    page = parse()
    hero = page.by_id("hero")
    assert hero is not None
    h1 = [e for e in page.elements if e.tag == "h1"]
    assert len(h1) == 1 and h1[0].text == HEADLINE
    assert any("subhead" in e.classes and e.text == SUBHEAD for e in page.elements)
    links = {(e.text, e.attrs.get("href")) for e in page.elements if e.tag == "a"}
    assert ("Get started", "#quickstart") in links
    assert ("View on GitHub", REPO_URL) in links


CLAIM_SECTIONS = ["pain-blocked", "pain-blind", "pain-bitten", "pain-burned", "github", "how"]


def claims_rows() -> list[tuple[str, str, str]]:
    rows = []
    for line in (SITE / "CLAIMS.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and line.lstrip().startswith("|") and not set(cells[0]) <= set("-: "):
            rows.append((cells[0], cells[1].strip("`"), cells[2]))
    return rows[1:]  # drop the header row


def test_claims_file_covers_sections():
    rows = claims_rows()
    covered = {section for _, section, _ in rows}
    for section in CLAIM_SECTIONS:
        assert section in covered, f"no claim row for #{section}"
    ids = set(parse().ids())
    for claim, section, backing in rows:
        assert section in ids, f"claim {claim!r}: section #{section} not on the page"
        for path in re.findall(r"`([^`]+)`", backing):
            assert (ROOT / path).exists(), f"claim {claim!r}: {path} does not exist"
        assert re.search(r"`[^`]+`", backing), f"claim {claim!r} has no backing path"
