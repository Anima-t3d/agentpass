"""Unix socket listener helpers: a group-restricted socket for the agent API.

The socket is bound under a private umask, handed to the configured group and only then
widened to 0660 and put into the listening state, so it is never reachable with a wrong
group. Access is limited to the owner and that group by the kernel, on top of the agent token.
"""

from __future__ import annotations

import contextlib
import grp
import os
import socket
import stat
from pathlib import Path

SOCKET_MODE = 0o660


class SocketSetupError(Exception):
    """The socket cannot be created safely; the gateway must not start."""


def _remove_stale(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise SocketSetupError(f"{path} exists and is not a socket; refusing to remove it")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(1)
        probe.connect(str(path))
    except OSError:
        pass  # nobody is listening: stale
    else:
        raise SocketSetupError(f"{path} is already in use by a running gateway")
    finally:
        probe.close()
    path.unlink()


def bind_group_socket(path: str, group: str) -> socket.socket:
    """Bind a Unix socket at ``path`` with mode 0660 and group ``group`` (not yet listening)."""
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        raise SocketSetupError(f"group {group!r} does not exist") from None
    sock_path = Path(path)
    sock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _remove_stale(sock_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setblocking(False)
    old_umask = os.umask(0o177)  # owner-only until the group is set
    try:
        sock.bind(path)
        try:
            os.chown(path, -1, gid)
        except PermissionError:
            raise SocketSetupError(
                f"cannot set group {group!r} on {path}: the service user must be a member"
            ) from None
        os.chmod(path, SOCKET_MODE)
    except BaseException:
        sock.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    finally:
        os.umask(old_umask)
    return sock


def remove_socket(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)
