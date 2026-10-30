"""The ``email`` renderer: ``gmail_send_message`` (docs/APPROVAL-PREVIEWS.md section 4.1).

The arg is the base64url RFC 5322 message that will be sent, byte for byte, and the
approval proof covers it. This decodes those same bytes. Text only: nothing is fetched,
no HTML is rendered, attachments are listed and never opened.
"""

from __future__ import annotations

import base64
import binascii
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlsplit

from agentpass.preview.htmltext import html_to_text
from agentpass.preview.model import LookupNote, Preview, Section, Unavailable
from agentpass.preview.renderers import _cap, _text
from agentpass.preview.sanitize import escape_unsafe

MAX_PARTS = 10
MAX_ATTACHMENTS = 20
MAX_LINKS = 20
BODY_LIMIT = 20_000
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_ADDRESS_HEADERS = ("From", "To", "Cc", "Bcc", "Reply-To")
_UNIQUE_HEADERS = ("From", "To", "Cc", "Bcc", "Subject", "Date", "Reply-To")
_WORD = re.compile(r"\w+")


def _domain_forms(domain: str) -> tuple[str, str]:
    """``(unicode form, ascii/punycode form)`` of a domain; unconvertible input is kept."""
    try:
        ascii_form = domain.encode("idna").decode("ascii")
        return ascii_form.encode("ascii").decode("idna"), ascii_form
    except UnicodeError:
        return domain, domain


def _address_text(display: str, local: str, domain: str, warnings: list[str]) -> str:
    uni, ascii_form = _domain_forms(domain)
    addr = f"{local}@{uni}" if domain else local
    if uni != ascii_form:
        addr += f" (punycode {ascii_form})"
        warnings.append(
            f"Domain {escape_unsafe(uni)} uses non-ASCII characters (punycode {ascii_form}); "
            "check it is the domain you expect"
        )
    if display:
        shown = escape_unsafe(display)
        if "@" in shown and shown.casefold() not in addr.casefold():
            warnings.append(f"Display name {shown!r} looks like an address but is not the real one")
        return f'"{shown}" <{escape_unsafe(addr)}>'
    return escape_unsafe(addr)


def _addresses(msg: EmailMessage, name: str, warnings: list[str]) -> list[tuple[str, str]]:
    """``[(shown, domain)]`` for every address in all headers called ``name``."""
    out: list[tuple[str, str]] = []
    for header in msg.get_all(name, []):
        try:
            found = list(header.addresses)
        except Exception:
            found = []
        if not found and str(header).strip():
            out.append((escape_unsafe(str(header)), ""))
            warnings.append(f"{name} header could not be read as an address list")
            continue
        for a in found:
            out.append(
                (_address_text(a.display_name, a.username, a.domain, warnings), a.domain.casefold())
            )
    return out


def _decoded_text(part: EmailMessage, warnings: list[str]) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return ""
        warnings.append("A text part has an unknown encoding; unreadable bytes were replaced")
        return payload.decode("utf-8", errors="replace")


def _norm_words(text: str) -> set[str]:
    return set(_WORD.findall(text.casefold()))


def _differ(plain: str, html_bare: str) -> bool:
    a, b = _norm_words(plain), _norm_words(html_bare)
    if not a and not b:
        return False
    return len(a & b) / max(1, len(a | b)) < 0.9


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").casefold()
    except ValueError:
        return ""


def _link_rows(
    plain: str, html_links: list[tuple[str, str]], warnings: list[str]
) -> list[list[str]]:
    rows: list[list[str]] = []
    seen: set[str] = set()
    mismatches = 0
    for shown, href in html_links:
        if href in seen:
            continue
        seen.add(href)
        note = ""
        looks_like_url = "://" in shown or shown.casefold().startswith("www.")
        if looks_like_url:
            shown_host = _host(shown if "://" in shown else f"http://{shown}")
            if shown_host and shown_host != _host(href):
                note = f"link text shows {escape_unsafe(shown_host)}"
                mismatches += 1
        rows.append([_host(href) or "(no host)", escape_unsafe(href), note])
    for url in _URL_RE.findall(plain):
        if url not in seen:
            seen.add(url)
            rows.append([_host(url) or "(no host)", escape_unsafe(url), ""])
    if mismatches:
        warnings.append(
            f"{mismatches} link(s) show one address but point to another; see the link list"
        )
    return rows[:MAX_LINKS]


def render_email(
    values: dict[str, Any],
    notes: list[LookupNote],
    *,
    params: dict[str, Any],
    max_chars: int,
    built_at: str,
) -> Preview | Unavailable:
    raw = values.get("raw")
    if not isinstance(raw, str):
        return Unavailable("message could not be decoded", built_at)
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        return Unavailable("message could not be decoded", built_at)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        return Unavailable("message could not be decoded", built_at)
    if not isinstance(msg, EmailMessage) or len(msg) == 0:
        return Unavailable("message could not be decoded", built_at)

    warnings: list[str] = []
    truncated = False
    head = data.split(b"\n\n", 1)[0].split(b"\r\n\r\n", 1)[0]
    if re.search(rb"\r(?!\n)", head):
        warnings.append("A header contains a bare line break (possible header smuggling)")
    names = [k.casefold() for k in msg]
    for name in _UNIQUE_HEADERS:
        if names.count(name.casefold()) > 1:
            warnings.append(f"Duplicate {name} header: check which one is used")
    if any(n.startswith("resent-") for n in names):
        warnings.append("Resent-* header present: it can add recipients or change the sender")
    if msg.defects or any(getattr(h, "defects", None) for h in msg.values()):
        warnings.append("The message has malformed headers")

    people = {n: _addresses(msg, n, warnings) for n in _ADDRESS_HEADERS}
    recipients = [a for n in ("To", "Cc", "Bcc") for a in people[n]]
    if not recipients:
        warnings.append("The message names no recipient")
    internal = params.get("internal_domains")
    if internal:
        wanted = {str(d).casefold() for d in internal}
        outside = sorted({shown for shown, dom in recipients if dom not in wanted})
        if outside:
            warnings.append("Recipient outside your domains: " + ", ".join(outside[:5]))

    subject = escape_unsafe(str(msg.get("Subject", "") or ""))
    header_rows: list[list[str]] = []
    for name in _ADDRESS_HEADERS:
        if people[name]:
            header_rows.append([name, ", ".join(s for s, _ in people[name])])
        elif name == "To":
            header_rows.append([name, "(none)"])
    header_rows.append(["Subject", _text(subject or "(none)", max_chars)])
    if msg.get("Date"):
        header_rows.append(["Date", _text(str(msg["Date"]), max_chars)])

    # Body and attachments, bounded
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []
    leaves = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        leaves += 1
        if leaves > MAX_PARTS:
            truncated = True
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            body = part.get_payload(decode=True)
            size = len(body) if isinstance(body, bytes) else 0
            if len(attachments) < MAX_ATTACHMENTS:
                attachments.append(
                    f"{_text(filename or '(unnamed)', 200)}: {escape_unsafe(ctype)}, {size:,} bytes"
                )
            continue
        if ctype == "text/plain":
            plain_parts.append(_decoded_text(part, warnings))
        elif ctype == "text/html":
            html_parts.append(_decoded_text(part, warnings))
        elif part.get_content_disposition() == "inline":
            attachments.append(f"(inline) {escape_unsafe(ctype)}")
    if leaves > MAX_PARTS:
        warnings.append(f"The message has {leaves} parts; only the first {MAX_PARTS} were read")

    plain = "\n\n".join(p for p in plain_parts if p).strip()
    html_text = html_bare = ""
    html_links: list[tuple[str, str]] = []
    if html_parts:
        html_text, html_bare, html_links = html_to_text("\n".join(html_parts))

    sections: list[Section] = [Section("kv", "Message", header_rows)]
    body_chars = len(plain) or len(html_text)

    def body_section(label: str, text: str) -> Section:
        nonlocal truncated
        shown = escape_unsafe(text) or "(empty)"
        if len(shown) > BODY_LIMIT:
            more = len(shown) - BODY_LIMIT
            shown = shown[:BODY_LIMIT] + f"\n… {more:,} more characters not shown"
            truncated = True
        return Section("text", label, shown)

    if plain:
        sections.append(body_section("Body", plain))
        if html_text and _differ(plain, html_bare):
            warnings.append("Plain and HTML parts differ; recipients may see different text")
            sections.append(body_section("HTML part, shown as text", html_text))
    elif html_text:
        sections.append(body_section("Body (HTML message, shown as text)", html_text))
    else:
        sections.append(Section("text", "Body", "(empty)"))

    link_rows = _link_rows(plain, html_links, warnings)
    if link_rows:
        sections.append(Section("table", "Links in the body (host, address, note)", link_rows))
    if attachments:
        sections.append(
            Section("list", "Attachments (names only, contents never opened)", attachments)
        )

    to_shown = [s for s, _ in people["To"]] or [s for s, _ in recipients]
    first = ", ".join(to_shown[:3]) + (f" +{len(to_shown) - 3} more" if len(to_shown) > 3 else "")
    title = f"Send email to {first}" if first else "Send email (no recipient)"
    count = len(attachments)
    tail = f"{count} attachment{'s' if count != 1 else ''} · {body_chars:,} chars"
    if params.get("telegram", "summary") == "minimal":
        lead = f"To: {first} · subject {len(subject)} chars"
    else:
        shown_subject = subject if len(subject) <= 60 else subject[:59] + "…"
        lead = f'To: {first} · "{shown_subject}"'
    return Preview(
        title=_cap(title),
        summary=_cap(f"{lead} · {tail}"),
        built_at=built_at,
        sections=sections,
        warnings=list(dict.fromkeys(warnings)),
        lookups=notes,
        truncated=truncated,
    )
