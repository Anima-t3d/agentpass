"""Socket-activated entry point: one JSON line in, one JSON line out (runs as agentgit).

Started per connection by systemd (Accept=yes); stdin/stdout are the connected socket.
Failures are reported as fixed error codes only; tracebacks go to stderr with the
token scrubbed.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import BinaryIO

from agentpass.gitmirror.fetch import FetchSettings, fetch, scrub
from agentpass.gitmirror.lookup import GitHubApi, GitHubHttpApi, lookup_commit, lookup_relation
from agentpass.gitmirror.validate import (
    HelperError,
    check_allowed,
    load_allowlist,
    parse_request,
    repo_path,
)

MAX_REQUEST = 4096
HOME = Path("/var/lib/agentgit")
ALLOWLIST = Path("/etc/agentgit/repos")
MIRROR_ROOT = Path("/srv/git-mirror")


def _read_line(stdin: BinaryIO) -> bytes:
    line = stdin.readline(MAX_REQUEST + 1)
    if line.endswith(b"\n"):
        line = line[:-1]
    if len(line) > MAX_REQUEST:
        raise HelperError("invalid_request")
    return line


def _parse(line: bytes) -> dict:
    try:
        raw = json.loads(line.decode("utf-8"))
    except ValueError:  # includes UnicodeDecodeError and JSONDecodeError
        raise HelperError("invalid_request") from None
    if not isinstance(raw, dict):
        raise HelperError("invalid_request")
    return raw


def _handle(
    raw: dict,
    settings: FetchSettings,
    allowlist_path: Path,
    mirror_root: Path,
    api: GitHubApi | None,
) -> dict:
    op, kind = raw.get("op"), raw.get("kind")
    if op == "ping":
        return {"ok": True}
    if op not in ("fetch", "lookup") or (op == "lookup" and kind not in ("commit", "relation")):
        raise HelperError("invalid_request")
    req = parse_request(raw)
    check_allowed(req, load_allowlist(allowlist_path))
    repo = repo_path(mirror_root, req)
    if op == "fetch":
        return {"ok": True, "result": fetch(req, repo, settings)}
    github = api if api is not None else GitHubHttpApi(settings.token)
    if kind == "commit":
        return {"ok": True, "result": lookup_commit(req, github)}
    return {"ok": True, "result": lookup_relation(req, repo, github, settings)}


def serve(
    stdin: BinaryIO,
    stdout: BinaryIO,
    settings: FetchSettings,
    allowlist_path: Path,
    mirror_root: Path,
    api: GitHubApi | None = None,
) -> None:
    try:
        response = _handle(_parse(_read_line(stdin)), settings, allowlist_path, mirror_root, api)
    except HelperError as e:
        response = {"ok": False, "error": e.code}
    except Exception:
        print(scrub(traceback.format_exc(), settings), file=sys.stderr)
        response = {"ok": False, "error": "internal"}
    stdout.write((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))
    stdout.flush()


def load_token() -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        return ""
    try:
        return (Path(directory) / "github-token").read_text().strip()
    except OSError:
        return ""


def main() -> None:
    os.umask(0o027)
    settings = FetchSettings(
        token=load_token(),
        home=HOME,
        trusted_uids=frozenset({0, os.getuid()}),
    )
    serve(
        sys.stdin.buffer,
        sys.stdout.buffer,
        settings,
        ALLOWLIST,
        MIRROR_ROOT,
    )


if __name__ == "__main__":
    main()
