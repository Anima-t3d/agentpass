"""The email renderer for gmail_send_message over the real tools/gmail.yaml."""

from __future__ import annotations

import json

from agentpass.preview import Unavailable
from tests.preview_helpers import build, build_any, mail, raw_mail, section


async def _email(msg, **kw):
    raw = raw_mail(msg) if not isinstance(msg, str) else msg
    return await build("gmail", "gmail", "gmail_send_message", {"raw": raw}, **kw)


async def test_plain_message_headers_body_and_summary():
    p = await _email(mail(Cc="carol@example.com", body="Dinner at 7?"))
    assert p.title == "Send email to bob@example.com"
    assert p.summary == 'To: bob@example.com · "Hello" · 0 attachments · 12 chars'
    headers = dict(section(p, "Message").data)
    assert headers["From"] == "alice@example.com" and headers["Cc"] == "carol@example.com"
    assert headers["Subject"] == "Hello"
    assert section(p, "Body").data.strip() == "Dinner at 7?"
    assert p.warnings == [] and p.status == "ok"


async def test_display_name_and_address_both_shown_and_bcc_listed():
    p = await _email(mail(to='"Boss" <x@evil.example>', Bcc="spy@example.net"))
    headers = dict(section(p, "Message").data)
    assert headers["To"] == '"Boss" <x@evil.example>'
    assert headers["Bcc"] == "spy@example.net"


async def test_idn_domain_shows_punycode_and_warns():
    p = await _email(mail(to="bob@bücher.example"))
    to = dict(section(p, "Message").data)["To"]
    assert "bücher.example" in to and "xn--bcher-kva.example" in to
    assert any("non-ASCII" in w for w in p.warnings)


async def test_display_name_that_looks_like_another_address_warns():
    p = await _email(mail(to='"ceo@example.com" <x@evil.example>'))
    assert any("looks like an address" in w for w in p.warnings)


async def test_duplicate_headers_resent_and_bare_cr_warn():
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\nTo: c@example.net\r\n"
        b"Resent-To: d@example.org\r\nSubject: s\r\nX-Odd: a\rb\r\n\r\nbody\r\n"
    )
    p = await _email(raw_mail(raw))
    joined = " | ".join(p.warnings)
    assert "Duplicate To header" in joined and "Resent-*" in joined and "bare line break" in joined


async def test_html_only_message_is_converted_to_text_without_scripts_or_remote_content():
    m = mail(body=None)
    m.set_content(
        "<html><head><style>p{color:red}</style><script>alert(1)</script></head><body>"
        '<p>Hi <b>Bob</b></p><img src="https://track.example/p.gif">'
        '<p>See <a href="https://example.com/doc">the doc</a></p><!-- hidden --></body></html>',
        subtype="html",
    )
    p = await _email(m)
    body = section(p, "Body (HTML message, shown as text)").data
    assert "Hi Bob" in body and "the doc [https://example.com/doc]" in body
    for forbidden in ("alert", "color:red", "track.example", "hidden", "<"):
        assert forbidden not in body
    links = section(p, "Links in the body (host, address, note)").data
    assert links == [["example.com", "https://example.com/doc", ""]]


async def test_plain_and_html_that_differ_warn_and_show_both():
    m = mail(body="See you at noon")
    m.add_alternative("<p>Wire the money to account 123 today</p>", subtype="html")
    p = await _email(m)
    assert any("Plain and HTML parts differ" in w for w in p.warnings)
    assert "HTML part, shown as text" in [s.label for s in p.sections]
    assert p.sections[1].label == "Body"  # plain first


async def test_matching_alternative_parts_do_not_warn():
    m = mail(body="Hello Bob see you soon")
    m.add_alternative("<p>Hello <b>Bob</b> see you soon</p>", subtype="html")
    p = await _email(m)
    assert p.warnings == [] and "HTML part, shown as text" not in [s.label for s in p.sections]


async def test_link_text_pointing_elsewhere_is_flagged():
    m = mail(body=None)
    m.set_content('<a href="https://evil.example/x">https://bank.example/login</a>', subtype="html")
    p = await _email(m)
    rows = section(p, "Links in the body (host, address, note)").data
    assert rows[0][0] == "evil.example" and "bank.example" in rows[0][2]
    assert any("point to another" in w for w in p.warnings)


async def test_attachments_are_listed_never_opened():
    m = mail()
    m.add_attachment(b"%PDF-1.4 secret", maintype="application", subtype="pdf", filename="plan.pdf")
    p = await _email(m)
    items = next(s.data for s in p.sections if s.label.startswith("Attachments"))
    assert items == ["plan.pdf: application/pdf, 15 bytes"]
    assert "secret" not in json.dumps(p.to_dict())
    assert "1 attachment " in p.summary


async def test_outside_internal_domain_warns_when_configured(tmp_path):
    from agentpass.config import load_tools_file
    from agentpass.preview import PreviewService
    from agentpass.registry import ToolRegistry
    from tests.preview_helpers import RoutedLookup

    (tmp_path / "t.yaml").write_text(
        "tools:\n  send:\n    args: {raw: {required: true}}\n"
        '    request: {method: POST, path: "/s"}\n'
        "    preview: {renderer: email, internal_domains: [example.com]}\n"
    )
    tools = load_tools_file(str(tmp_path / "t.yaml"), "svc")
    svc = PreviewService(ToolRegistry({t.name: t for t in tools}), {"svc": RoutedLookup({})})
    p = await svc.build("send", {"raw": raw_mail(mail(to="bob@example.com, eve@other.example"))})
    assert p.warnings == ["Recipient outside your domains: eve@other.example"]


async def test_large_body_is_truncated_and_labelled():
    p = await _email(mail(body="x" * 30_000))
    assert p.truncated and p.status == "partial" and "preview is partial" in p.warnings
    assert "10,000 more characters not shown" in section(p, "Body").data


async def test_hostile_subject_and_body_stay_plain_and_escaped():
    p = await _email(mail(subject="<script>alert(1)</script>‮evil", body="<b>x</b>\x07"))
    dumped = json.dumps(p.to_dict(), ensure_ascii=False)
    assert "‮" not in dumped and "\\u202e" in dumped and "\\u0007" in dumped
    assert dict(section(p, "Message").data)["Subject"].startswith("<script>")  # text, never markup


async def test_many_parts_are_capped():
    m = mail()
    for i in range(14):
        m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=f"f{i}")
    p = await _email(m)
    assert p.truncated and any("only the first 10" in w for w in p.warnings)


async def test_minimal_telegram_summary_omits_the_subject():
    from agentpass.preview.email_render import render_email

    p = render_email(
        {"raw": raw_mail(mail(subject="Secret plans"))},
        [],
        params={"telegram": "minimal"},
        max_chars=2000,
        built_at="2026-10-29T10:00:00Z",
    )
    assert "Secret" not in p.summary and "subject 12 chars" in p.summary


async def test_undecodable_message_is_unavailable():
    for raw in ("@@@", raw_mail(b"")):
        result = await build_any("gmail", "gmail", "gmail_send_message", {"raw": raw})
        assert isinstance(result, Unavailable)
        assert result.reason == "message could not be decoded"
