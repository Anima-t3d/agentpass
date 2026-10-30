"""The diff renderer for gh_put_contents over the real tools/github.yaml."""

from __future__ import annotations

import json

from agentpass.preview import Unavailable
from agentpass.services.http import HTTPServiceError
from tests.preview_helpers import b64, build, build_any, fixture, section

SHA = "a" * 40
CONTENTS = "/repos/{owner}/{repo}/contents/{path:path}"
REPO = "/repos/{owner}/{repo}"
OLD = "# Shiny app\n\nOne line.\n"


def args(new: str | bytes, **kw):
    base = {
        "owner": "example-org", "repo": "shiny-app", "branch": "feat/readme",
        "path": "README.md", "message": "Update the readme", "content": b64(new), "sha": SHA,
    }  # fmt: skip
    base.update(kw)
    return {k: v for k, v in base.items() if v is not None}


def routes(current=None, repo=None, **extra):
    r = {CONTENTS: current if current is not None else fixture("gh/contents_readme")}
    r[REPO] = repo if repo is not None else {"default_branch": "main"}
    r.update(extra)
    return r


async def _put(a, r):
    return await build("github", "github", "gh_put_contents", a, r)


async def test_modify_shows_diff_counts_and_matching_base():
    p = await _put(args("# Shiny app\n\nTwo lines.\nAnother.\n"), routes())
    assert p.title == "Change README.md on example-org/shiny-app@feat/readme"
    assert p.summary.endswith(": +2 -1")
    diff = section(p, "Changes").data
    assert "-One line." in diff and "+Two lines." in diff and diff.startswith("--- a/README.md")
    change = dict(section(p, "Change").data)
    assert change["Mode"] == "modifies existing file" and change["Lines"] == "+2 / -1"
    assert change["Base"] == "Diff is against the version the agent based its change on"
    assert section(p, "Commit message").data == "Update the readme"
    assert p.warnings == []


async def test_stale_base_sha_warns_and_names_the_409():
    p = await _put(args("x\n", sha="b" * 40), routes())
    assert any("File changed since the agent read it" in w and "409" in w for w in p.warnings)
    assert dict(section(p, "Change").data)["Base"] == "File changed since the agent read it"


async def test_new_file_when_the_lookup_is_404():
    p = await _put(args("hello\n", sha=None), {REPO: {"default_branch": "main"}})
    assert p.title.startswith("Create README.md")
    assert dict(section(p, "Change").data)["Mode"] == "new file"
    assert section(p, "New file content").data.count("\n+hello") == 1
    assert p.warnings == []


async def test_new_file_but_sha_given_warns():
    p = await _put(args("hello\n"), {REPO: {"default_branch": "main"}})
    assert any("does not exist" in w for w in p.warnings)


async def test_existing_file_without_sha_warns_422():
    p = await _put(args("x\n", sha=None), routes())
    assert any("422" in w for w in p.warnings)


async def test_identical_content_is_labelled_no_change():
    p = await _put(args(OLD), routes())
    assert dict(section(p, "Change").data)["Mode"] == "no change"
    assert any("no change" in w for w in p.warnings)
    assert not any(s.kind == "diff" for s in p.sections)


async def test_default_branch_warning_from_lookup_and_fallback():
    p = await _put(args("x\n", branch="trunk"), routes(repo={"default_branch": "trunk"}))
    assert "Writes directly to the default branch" in p.warnings
    # lookup failed: fall back to the usual names
    p = await _put(
        args("x\n", branch="main"),
        {CONTENTS: fixture("gh/contents_readme"), REPO: HTTPServiceError("HTTP 500")},
    )
    assert "Writes directly to the default branch" in p.warnings


async def test_binary_content_shows_hashes_not_a_diff():
    p = await _put(args(b"\x89PNG\x00\x01\x02"), routes())
    assert not any(s.kind == "diff" for s in p.sections)
    change = dict(section(p, "Change").data)
    assert len(change["New sha256"]) == 64 and len(change["Current sha256"]) == 64
    assert "Binary content: no diff shown" in p.warnings


async def test_oversized_current_file_shows_sizes_and_sha_only():
    big = dict(fixture("gh/contents_readme"), size=900_000, content="", encoding="none")
    p = await _put(args("x\n"), routes(current=big))
    assert "Diff not shown (current file too large)" in p.warnings
    change = dict(section(p, "Change").data)
    assert change["Current size"] == "900,000 bytes" and change["Current blob sha"] == SHA
    assert not any(s.kind == "diff" for s in p.sections)


async def test_response_too_large_is_also_the_oversized_case():
    p = await _put(args("x\n"), routes(current=HTTPServiceError("response too large")))
    assert "Diff not shown (current file too large)" in p.warnings


async def test_large_diff_is_truncated_and_labelled():
    new = "".join(f"line {i}\n" for i in range(1000))
    p = await _put(args(new), {REPO: {"default_branch": "main"}})
    diff = section(p, "New file content").data
    assert p.truncated and p.status == "partial" and "preview is partial" in p.warnings
    assert diff.rstrip().endswith("more diff lines not shown")
    assert len(diff.splitlines()) <= 402
    assert p.summary.endswith("+1000 -0")


async def test_lookup_failure_other_than_404_degrades_to_hashes():
    p = await _put(
        args("x\n"), {CONTENTS: HTTPServiceError("HTTP 500"), REPO: {"default_branch": "main"}}
    )
    assert any("Current file could not be read (HTTP 500)" in w for w in p.warnings)
    assert dict(section(p, "Change").data)["Mode"] == "unknown (lookup failed)"


async def test_directory_and_path_warnings():
    p = await _put(args("x\n", path=".github/workflows/ci.yml"), routes(current=[{"name": "a"}]))
    assert any("directory" in w for w in p.warnings)
    assert any("Changes CI" in w for w in p.warnings)
    p = await _put(args("x\n", path=".gitmodules"), routes())
    assert any(".gitmodules" in w for w in p.warnings)
    p = await _put(args("x\n", path="a/../b"), routes())
    assert any("'..'" in w for w in p.warnings)


async def test_hostile_text_is_escaped_in_diff_message_and_path():
    p = await _put(args("<script>‮\n", message="m‮", path="a‮b.txt"), {})
    dumped = json.dumps(p.to_dict(), ensure_ascii=False)
    assert "‮" not in dumped and "\\u202e" in dumped
    assert any("control or direction" in w for w in p.warnings)


async def test_invalid_base64_is_unavailable():
    r = await build_any(
        "github", "github", "gh_put_contents", args("x") | {"content": "!!!"}, routes()
    )
    assert isinstance(r, Unavailable) and r.reason == "content is not valid base64"


async def test_preview_makes_only_get_lookups_and_never_executes():
    from tests.preview_helpers import service

    svc, fake = service("github", "github", routes())
    await svc.build("gh_put_contents", args("x\n"))
    assert sorted(fake.paths) == sorted([CONTENTS, REPO])
