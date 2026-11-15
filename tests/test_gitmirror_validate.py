from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentpass.gitmirror.validate import (
    FetchRequest,
    HelperError,
    check_allowed,
    check_path_safe,
    load_allowlist,
    parse_request,
    repo_path,
)

SHA = "a" * 40
TRUSTED = frozenset({0, os.getuid()})


def req(**over: str) -> dict:
    base = {"owner": "octo", "repo": "hello", "branch": "main", "sha": SHA}
    base.update(over)
    return base


@pytest.mark.parametrize(
    "field,value",
    [
        ("branch", "-x"),
        ("branch", "a..b"),
        ("branch", "x.lock"),
        ("branch", "a//b"),
        ("branch", "/a"),
        ("branch", "a/"),
        ("branch", ".hidden"),
        ("branch", "a/.b"),
        ("branch", "x@{1}"),
        ("branch", "a\\b"),
        ("branch", "a\x01"),
        ("branch", "a\n"),
        ("branch", "a" * 256),
        ("owner", "-o"),
        ("owner", "o-"),
        ("owner", "a" * 40),
        ("repo", ".."),
        ("repo", "."),
        ("repo", "a/b"),
        ("repo", "a" * 101),
        ("sha", "A" * 40),
        ("sha", "a" * 39),
        ("sha", "a" * 41),
        ("sha", SHA + "\n"),
    ],
)
def test_parse_request_refuses(field: str, value: str) -> None:
    with pytest.raises(HelperError) as ei:
        parse_request(req(**{field: value}))
    assert ei.value.code == "invalid_request"
    assert str(ei.value) == "invalid_request"


def test_parse_request_refuses_extra_key_and_non_string() -> None:
    with pytest.raises(HelperError):
        parse_request({**req(), "extra": "x"})
    with pytest.raises(HelperError):
        parse_request(req(sha=5))  # type: ignore[arg-type]
    with pytest.raises(HelperError):
        parse_request({"owner": "o", "repo": "r", "branch": "main"})


def test_parse_request_ignores_op_and_kind() -> None:
    out = parse_request({**req(), "op": "fetch", "kind": "branch"})
    assert out == FetchRequest("octo", "hello", "main", SHA)


@pytest.mark.parametrize("branch", ["feat/x", "ccr-3934ca75-urhwdh", "release-1.2_x"])
def test_parse_request_accepts_slash_branches(branch: str) -> None:
    assert parse_request(req(branch=branch)).branch == branch


def test_parse_request_accepts_sha256() -> None:
    assert parse_request(req(sha="b" * 64)).sha == "b" * 64


def test_load_allowlist_and_not_in_allowlist_refused(tmp_path: Path) -> None:
    f = tmp_path / "repos"
    f.write_text("# comment\n\n octo/hello \nother/Thing\n")
    allow = load_allowlist(f)
    assert allow == frozenset({"octo/hello", "other/Thing"})
    check_allowed(parse_request(req()), allow)
    with pytest.raises(HelperError) as ei:
        check_allowed(parse_request(req(owner="OCTO")), allow)
    assert ei.value.code == "not_allowed"
    assert str(ei.value) == "not_allowed"


def test_missing_owner_dir_is_not_configured(tmp_path: Path) -> None:
    r = parse_request(req())
    with pytest.raises(HelperError) as ei:
        repo_path(tmp_path, r)
    assert ei.value.code == "not_configured"
    assert not (tmp_path / "octo").exists()
    (tmp_path / "octo").mkdir()
    assert repo_path(tmp_path, r) == tmp_path / "octo" / "hello.git"
    assert not (tmp_path / "octo" / "hello.git").exists()


def make_tree(tmp_path: Path) -> Path:
    a = tmp_path / "a"
    b = a / "b"
    b.mkdir(parents=True)
    for d in (a, b):
        d.chmod(0o755)
    return b


def test_path_safety_clean_tree_passes(tmp_path: Path) -> None:
    check_path_safe(make_tree(tmp_path), TRUSTED)


@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_path_safety_refuses_group_or_other_writable(tmp_path: Path, mode: int) -> None:
    b = make_tree(tmp_path)
    b.parent.chmod(mode)
    with pytest.raises(HelperError) as ei:
        check_path_safe(b, TRUSTED)
    assert ei.value.code == "unsafe_path"


def test_path_safety_refuses_untrusted_owner(tmp_path: Path) -> None:
    b = make_tree(tmp_path)
    with pytest.raises(HelperError) as ei:
        check_path_safe(b, frozenset({0}) - {os.getuid()})
    assert ei.value.code == "unsafe_path"


def test_path_safety_refuses_symlink_component(tmp_path: Path) -> None:
    b = make_tree(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(b.parent)
    with pytest.raises(HelperError) as ei:
        check_path_safe(link / "b", TRUSTED)
    assert ei.value.code == "unsafe_path"


def test_path_safety_root_sticky_dir_accepted() -> None:
    st = os.lstat("/tmp")
    if st.st_uid != 0 or not st.st_mode & 0o1000:
        pytest.skip("/tmp is not root-owned sticky here")
    check_path_safe(Path("/tmp"), frozenset({0}))


def test_path_safety_non_root_sticky_other_writable_refused(tmp_path: Path) -> None:
    b = make_tree(tmp_path)
    b.chmod(0o1777)
    with pytest.raises(HelperError) as ei:
        check_path_safe(b, TRUSTED)
    assert ei.value.code == "unsafe_path"
