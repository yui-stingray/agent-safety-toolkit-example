#!/usr/bin/env python3
"""Crash-consistent publication for the demo's three fixed evidence files.

This helper targets the repository's documented CPython 3.12 / Ubuntu Linux
local-filesystem contract.  It uses advisory ``flock``, ``fsync``, ordinary
atomic rename semantics, ``/proc``, and Linux pidfds; it does not claim
equivalent behavior on network filesystems or other operating systems.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - the documented target is POSIX.
    fcntl = None  # type: ignore[assignment]


AUDIT_EVENT_PROFILE = "agent-guard.public_agent_policy_audit_event.v1"
JOURNAL_SCHEMA = "agent-safety-toolkit.evidence-publication.v1"
STAGE_SCHEMA = "agent-safety-toolkit.evidence-stage.v1"
TRANSACTION_SCHEMA = "agent-safety-toolkit.evidence-transaction.v1"
STATE_DIR_SUFFIX = ".agent-safety-evidence-state"
STAGE_MARKER = ".agent-safety-stage.json"
STAGE_RUNTIME = "runtime"
TRANSACTION_MARKER = ".agent-safety-transaction.json"
JOURNAL_NAME = "journal.json"
LOCK_NAME = "publication.lock"
TRANSACTION_PREPARATION_PREFIX = "transaction-preparing-"
STAGE_BACKUP_PREFIX = ".agent-safety-toolkit-example-evidence."

ARTIFACTS: tuple[tuple[str, Path], ...] = (
    ("report", Path(".agent-guard/evidence/agent-guard-report.json")),
    ("manifest", Path(".agent-guard/evidence/agent-guard-evidence-pack.json")),
    ("event", Path(".agent-policy/evidence/policy-admission-event.json")),
)
EVIDENCE_FILENAMES = {
    "agent-guard-evidence-pack.json",
    "agent-guard-report.json",
}
_GIT_LOCAL_ENVIRONMENT_VARIABLES = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}
_SYS_PIDFD_SEND_SIGNAL = 424
_SYS_PIDFD_OPEN = 434
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


class PublicationError(RuntimeError):
    """A sanitized publication failure."""


class WriterBusy(PublicationError):
    """Another writer currently owns the advisory lock."""


class _TerminationRequested(BaseException):
    """The active publication received a deferred termination request."""


@dataclass
class _TerminationController:
    wakeup_read_fd: int
    signal_number: int | None = None
    signal_count: int = 0

    def handle(self, signum: int, _frame: Any) -> None:
        self.signal_count += 1
        if self.signal_number is None:
            self.signal_number = signum

    def raise_if_pending(self) -> None:
        if self.signal_number is not None:
            raise _TerminationRequested

    @property
    def exit_code(self) -> int:
        return 130 if self.signal_number == signal.SIGINT else 143

    @property
    def diagnostic(self) -> str:
        return (
            "evidence publication interrupted"
            if self.signal_number == signal.SIGINT
            else "evidence publication terminated"
        )

    def drain_wakeup(self) -> None:
        while True:
            try:
                if not os.read(self.wakeup_read_fd, 4096):
                    return
            except BlockingIOError:
                return

    def wait_for_signal_count(self, expected_count: int) -> None:
        poller = select.poll()
        poller.register(self.wakeup_read_fd, select.POLLIN)
        while self.signal_count < expected_count:
            try:
                poller.poll()
            except InterruptedError:
                pass
            self.drain_wakeup()

    def wait_for_process(self, pidfd: int) -> bool:
        if self.signal_number is not None:
            return True
        poller = select.poll()
        poller.register(self.wakeup_read_fd, select.POLLIN)
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            try:
                events = poller.poll()
            except InterruptedError:
                events = []
            self.drain_wakeup()
            if self.signal_number is not None:
                return True
            if any(fd == pidfd for fd, _event in events):
                return False

    @contextmanager
    def commit_linearization(self) -> Iterator[None]:
        watched = {signal.SIGINT, signal.SIGTERM}
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
        try:
            self.drain_wakeup()
            pending = signal.sigpending() & watched
            if pending and self.signal_number is None:
                self.signal_number = (
                    signal.SIGINT if signal.SIGINT in pending else signal.SIGTERM
                )
            if self.signal_number is not None:
                raise _TerminationRequested
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            self.drain_wakeup()


@contextmanager
def _coalesced_termination() -> Iterator[_TerminationController]:
    wakeup_read, wakeup_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    controller = _TerminationController(wakeup_read)
    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_wakeup = signal.set_wakeup_fd(wakeup_write, warn_on_full_buffer=False)
    signal.signal(signal.SIGINT, controller.handle)
    signal.signal(signal.SIGTERM, controller.handle)
    try:
        yield controller
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)
        signal.set_wakeup_fd(previous_wakeup)
        os.close(wakeup_write)
        os.close(wakeup_read)


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    state: str
    process_group: int
    session: int
    start_identity: int


@dataclass(frozen=True)
class _PinnedProcess:
    identity: _ProcessIdentity
    pidfd: int


@dataclass(frozen=True)
class _PinnedDirectory:
    fd: int
    parent_fd: int | None
    name: str | None
    device: int
    inode: int


@dataclass(frozen=True)
class _LiveArtifact:
    role: str
    relative: Path
    directory: _PinnedDirectory
    name: str


@dataclass(frozen=True)
class _LiveArtifacts:
    repo_path: Path
    repo: _PinnedDirectory
    directories: tuple[_PinnedDirectory, ...]
    artifacts: tuple[_LiveArtifact, ...]
    guard_evidence: _PinnedDirectory

    def by_role(self) -> dict[str, _LiveArtifact]:
        return {artifact.role: artifact for artifact in self.artifacts}


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _pinned_directory(fd: int, parent_fd: int | None, name: str | None) -> _PinnedDirectory:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        raise PublicationError("evidence publication input is invalid")
    return _PinnedDirectory(fd, parent_fd, name, metadata.st_dev, metadata.st_ino)


def _open_directory_at(parent: _PinnedDirectory, name: str, *, create: bool) -> _PinnedDirectory:
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent.fd)
    except FileNotFoundError:
        if not create:
            raise PublicationError("evidence publication set is incomplete")
        try:
            os.mkdir(name, 0o755, dir_fd=parent.fd)
            os.fsync(parent.fd)
        except FileExistsError:
            pass
        try:
            fd = os.open(name, _directory_flags(), dir_fd=parent.fd)
        except OSError as exc:
            raise PublicationError("evidence publication input is invalid") from exc
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    try:
        return _pinned_directory(fd, parent.fd, name)
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _open_live_artifacts(repo: Path, *, create_parents: bool) -> Iterator[_LiveArtifacts]:
    descriptors: list[int] = []
    try:
        root_fd = os.open(repo, _directory_flags())
        descriptors.append(root_fd)
        root = _pinned_directory(root_fd, None, None)
        guard = _open_directory_at(root, ".agent-guard", create=create_parents)
        descriptors.append(guard.fd)
        guard_evidence = _open_directory_at(guard, "evidence", create=create_parents)
        descriptors.append(guard_evidence.fd)
        policy = _open_directory_at(root, ".agent-policy", create=create_parents)
        descriptors.append(policy.fd)
        policy_evidence = _open_directory_at(policy, "evidence", create=create_parents)
        descriptors.append(policy_evidence.fd)
        artifacts = (
            _LiveArtifact("report", ARTIFACTS[0][1], guard_evidence, ARTIFACTS[0][1].name),
            _LiveArtifact(
                "manifest", ARTIFACTS[1][1], guard_evidence, ARTIFACTS[1][1].name
            ),
            _LiveArtifact("event", ARTIFACTS[2][1], policy_evidence, ARTIFACTS[2][1].name),
        )
        live = _LiveArtifacts(
            repo,
            root,
            (guard, guard_evidence, policy, policy_evidence),
            artifacts,
            guard_evidence,
        )
        _assert_live_bindings(live)
        yield live
    except PublicationError:
        raise
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _assert_live_bindings(live: _LiveArtifacts) -> None:
    try:
        root_metadata = os.stat(live.repo_path, follow_symlinks=False)
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_dev != live.repo.device
        or root_metadata.st_ino != live.repo.inode
    ):
        raise PublicationError("evidence publication input is invalid")
    for directory in live.directories:
        assert directory.parent_fd is not None and directory.name is not None
        try:
            metadata = os.stat(
                directory.name,
                dir_fd=directory.parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PublicationError("evidence publication input is invalid") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != directory.device
            or metadata.st_ino != directory.inode
        ):
            raise PublicationError("evidence publication input is invalid")


def _open_regular_at(directory_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(fd)
        raise PublicationError("evidence publication input is invalid")
    return fd


def _digest_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    encoded = base64.b32encode(digest.digest()).decode("ascii")
    return "b" + encoded.rstrip("=").lower()


def _digest_live(artifact: _LiveArtifact) -> str:
    fd = _open_regular_at(artifact.directory.fd, artifact.name)
    try:
        return _digest_fd(fd)
    finally:
        os.close(fd)


def _live_stat(artifact: _LiveArtifact) -> os.stat_result | None:
    try:
        metadata = os.stat(
            artifact.name,
            dir_fd=artifact.directory.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PublicationError("evidence publication input is invalid")
    return metadata


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with _open_regular_file(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    encoded = base64.b32encode(digest.digest()).decode("ascii")
    return "b" + encoded.rstrip("=").lower()


@contextmanager
def _open_regular_file(path: Path) -> Iterator[Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PublicationError("evidence publication input is invalid")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            yield handle
    finally:
        os.close(fd)


def _fsync_file(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags | nofollow)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PublicationError("evidence publication state is invalid")
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_bytes_durable(path: Path, payload: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    _fsync_directory(path.parent)


def _write_json_durable(path: Path, payload: dict[str, Any]) -> None:
    serialized = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    _write_bytes_durable(path, serialized)


def _replace_json_durable(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    _write_json_durable(temporary, payload)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _copy_file_durable(
    source: Path,
    destination: Path,
    mode: int | None = None,
    *,
    temporary_path: Path | None = None,
    pause_point: str | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = temporary_path or (
        destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    )
    if temporary.parent != destination.parent:
        raise PublicationError("evidence publication state is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, mode if mode is not None else 0o600)
        try:
            if mode is not None:
                os.fchmod(fd, mode)
            if pause_point is not None:
                _pause_for_test(pause_point)
            with (
                _open_regular_file(source) as input_handle,
                os.fdopen(fd, "wb", closefd=False) as output,
            ):
                shutil.copyfileobj(input_handle, output)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(fd)
        if mode is None:
            os.chmod(temporary, stat.S_IMODE(os.lstat(source).st_mode))
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if (
            os.path.lexists(temporary)
            and temporary.is_file()
            and not temporary.is_symlink()
        ):
            temporary.unlink()
        raise


def _copy_live_to_private_durable(
    artifact: _LiveArtifact, destination: Path, *, mode: int | None = None
) -> None:
    source_fd = _open_regular_at(artifact.directory.fd, artifact.name)
    temporary: Path | None = None
    try:
        source_mode = stat.S_IMODE(os.fstat(source_fd).st_mode)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        output_fd = os.open(temporary, flags, mode if mode is not None else 0o600)
        try:
            os.fchmod(output_fd, mode if mode is not None else source_mode)
            os.lseek(source_fd, 0, os.SEEK_SET)
            while chunk := os.read(source_fd, 1024 * 1024):
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    view = view[written:]
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException as exc:
        if temporary is not None and os.path.lexists(temporary):
            if temporary.is_symlink() or not temporary.is_file():
                raise PublicationError(
                    "evidence publication state is invalid"
                ) from exc
            temporary.unlink()
        raise
    finally:
        os.close(source_fd)


def _remove_live_temporary(artifact: _LiveArtifact, temporary_name: str) -> None:
    try:
        metadata = os.stat(
            temporary_name,
            dir_fd=artifact.directory.fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublicationError("evidence publication state is invalid") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PublicationError("evidence publication state is invalid")
    os.unlink(temporary_name, dir_fd=artifact.directory.fd)
    os.fsync(artifact.directory.fd)


def _copy_private_to_live_durable(
    source: Path,
    artifact: _LiveArtifact,
    *,
    mode: int,
    temporary_name: str,
    pause_point: str | None = None,
) -> None:
    _remove_live_temporary(artifact, temporary_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        output_fd = os.open(
            temporary_name,
            flags,
            mode,
            dir_fd=artifact.directory.fd,
        )
        try:
            os.fchmod(output_fd, mode)
            if pause_point is not None:
                _pause_for_test(pause_point)
            with _open_regular_file(source) as input_handle:
                while chunk := input_handle.read(1024 * 1024):
                    view = memoryview(chunk)
                    while view:
                        written = os.write(output_fd, view)
                        view = view[written:]
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
        os.replace(
            temporary_name,
            artifact.name,
            src_dir_fd=artifact.directory.fd,
            dst_dir_fd=artifact.directory.fd,
        )
        destination_fd = _open_regular_at(artifact.directory.fd, artifact.name)
        try:
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        os.fsync(artifact.directory.fd)
    except BaseException:
        _remove_live_temporary(artifact, temporary_name)
        raise


def _unlink_live_regular(artifact: _LiveArtifact) -> None:
    metadata = _live_stat(artifact)
    if metadata is None:
        return
    os.unlink(artifact.name, dir_fd=artifact.directory.fd)
    os.fsync(artifact.directory.fd)


def _read_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PublicationError("evidence publication state is invalid")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationError("evidence publication state is invalid") from exc
    if not isinstance(payload, dict):
        raise PublicationError("evidence publication state is invalid")
    return payload


def _state_directory(repo: Path) -> Path:
    return repo.parent / f".{repo.name}{STATE_DIR_SUFFIX}"


def _ensure_state_directory(repo: Path) -> Path:
    state = _state_directory(repo)
    if not os.path.lexists(state):
        try:
            state.mkdir(mode=0o700)
            _fsync_directory(state.parent)
        except FileExistsError:
            pass
    if state.is_symlink() or not state.is_dir():
        raise PublicationError("evidence publication state is invalid")
    os.chmod(state, 0o700)
    return state


def _create_test_marker(variable: str) -> None:
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TESTING") != "1":
        return
    raw_path = os.environ.get(variable)
    if not raw_path:
        return
    marker = Path(raw_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("ready\n", encoding="utf-8")
    _fsync_file(marker)
    _fsync_directory(marker.parent)


def _pause_for_test(
    point: str, termination: _TerminationController | None = None
) -> None:
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TESTING") != "1":
        return
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TEST_PAUSE_AT") != point:
        return
    expected_count = termination.signal_count + 1 if termination is not None else None
    _create_test_marker("AGENT_SAFETY_EVIDENCE_TEST_MARKER")
    if termination is None:
        signal.pause()
        return
    termination.wait_for_signal_count(expected_count)


def _pause_once_for_test(
    point: str, termination: _TerminationController | None = None
) -> None:
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TESTING") != "1":
        return
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TEST_PAUSE_AT") != point:
        return
    expected_count = termination.signal_count + 1 if termination is not None else None
    _create_test_marker("AGENT_SAFETY_EVIDENCE_TEST_MARKER")
    if termination is None:
        signal.pause()
        return
    termination.wait_for_signal_count(expected_count)


@contextmanager
def _publication_lock(
    state: Path, *, blocking: bool, reader: bool = False
) -> Iterator[None]:
    if fcntl is None:
        raise PublicationError(
            "evidence publication requires the documented POSIX platform"
        )
    lock_path = state / LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise PublicationError("evidence publication state is invalid") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PublicationError("evidence publication state is invalid")
        os.fchmod(fd, 0o600)
        if reader:
            _create_test_marker("AGENT_SAFETY_EVIDENCE_TEST_READER_WAIT_MARKER")
        operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(fd, operation)
        except OSError as exc:
            if not blocking and exc.errno in (errno.EACCES, errno.EAGAIN):
                raise WriterBusy(
                    "evidence publication or snapshot consumption is already in progress"
                ) from exc
            raise PublicationError("evidence publication lock failed") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _pid_is_alive(value: Any) -> bool:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_process_identity(pid: int) -> _ProcessIdentity | None:
    if pid <= 0:
        return None
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    _prefix, separator, suffix = payload.rpartition(")")
    if not separator:
        return None
    fields = suffix.split()
    if (
        len(fields) <= 19
        or not fields[2].isdigit()
        or not fields[3].isdigit()
        or not fields[19].isdigit()
    ):
        return None
    return _ProcessIdentity(
        pid=pid,
        state=fields[0],
        process_group=int(fields[2]),
        session=int(fields[3]),
        start_identity=int(fields[19]),
    )


def _process_start_identity(pid: int) -> int | None:
    identity = _read_process_identity(pid)
    return identity.start_identity if identity is not None else None


def _process_session_identity(pid: int) -> int | None:
    identity = _read_process_identity(pid)
    return identity.session if identity is not None else None


def _process_group_identity(pid: int) -> int | None:
    identity = _read_process_identity(pid)
    return identity.process_group if identity is not None else None


def _session_member_pids(session_id: int) -> set[int]:
    members: set[int] = set()
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise PublicationError("safe process isolation is unavailable") from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if _process_session_identity(pid) == session_id:
            members.add(pid)
    return members


def _session_executable_member_pids(session_id: int) -> set[int]:
    members: set[int] = set()
    for pid in _session_member_pids(session_id):
        identity = _read_process_identity(pid)
        if identity is not None and identity.state not in {"Z", "X", "x"}:
            members.add(pid)
    return members


def _pidfd_open(pid: int) -> int | None:
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        ctypes.c_long(_SYS_PIDFD_OPEN),
        ctypes.c_int(pid),
        ctypes.c_uint(0),
    )
    if result >= 0:
        return int(result)
    error = ctypes.get_errno()
    if error == errno.ESRCH:
        return None
    raise PublicationError("safe process isolation is unavailable")


def _pidfd_send_signal(pidfd: int, signum: int) -> bool:
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        ctypes.c_long(_SYS_PIDFD_SEND_SIGNAL),
        ctypes.c_int(pidfd),
        ctypes.c_int(signum),
        ctypes.c_void_p(),
        ctypes.c_uint(0),
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.ESRCH:
        return False
    raise PublicationError("safe process isolation is unavailable")


def _require_pidfd_support() -> None:
    pidfd = _pidfd_open(os.getpid())
    if pidfd is None:
        raise PublicationError("safe process isolation is unavailable")
    try:
        if not _pidfd_send_signal(pidfd, 0):
            raise PublicationError("safe process isolation is unavailable")
    finally:
        os.close(pidfd)


def _pin_session_member(pid: int, session_id: int) -> _PinnedProcess | None:
    before = _read_process_identity(pid)
    if before is None or before.session != session_id:
        return None
    pidfd = _pidfd_open(pid)
    if pidfd is None:
        return None
    after = _read_process_identity(pid)
    if (
        after is None
        or after.session != session_id
        or after.start_identity != before.start_identity
    ):
        os.close(pidfd)
        return None
    return _PinnedProcess(identity=after, pidfd=pidfd)


def _process_identity_is_alive(pid: Any, start_identity: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if start_identity is not None and (
        not isinstance(start_identity, int) or isinstance(start_identity, bool)
    ):
        return False
    identity = _read_process_identity(pid)
    if identity is not None:
        if identity.state in {"Z", "X", "x"}:
            return False
        if start_identity is not None:
            return identity.start_identity == start_identity
        return True
    if start_identity is not None:
        return False
    return _pid_is_alive(pid)


def _isolated_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in _GIT_LOCAL_ENVIRONMENT_VARIABLES or name.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            environment.pop(name)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _remove_stage(repo: Path, container: Path) -> None:
    worktree = container / "worktree"
    if (repo / ".git").exists() and (worktree / ".git").exists():
        removed = subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
            env=_isolated_git_environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        if removed.returncode != 0:
            raise PublicationError("working-tree staging cleanup failed")
    if worktree.exists():
        shutil.rmtree(worktree)
    runtime = container / STAGE_RUNTIME
    if runtime.exists():
        if runtime.is_symlink() or not runtime.is_dir():
            raise PublicationError("evidence publication state is invalid")
        shutil.rmtree(runtime)
    for backup in container.glob(f"{STAGE_BACKUP_PREFIX}*"):
        if backup.is_symlink() or not backup.is_dir():
            raise PublicationError("evidence publication state is invalid")
        shutil.rmtree(backup)
    for temporary in container.glob(f".{STAGE_MARKER}.*.tmp"):
        if temporary.is_symlink() or not temporary.is_file():
            raise PublicationError("evidence publication state is invalid")
        temporary.unlink()
    marker = container / STAGE_MARKER
    if marker.exists():
        marker.unlink()
    if container.exists():
        if any(container.iterdir()):
            raise PublicationError("evidence publication state is invalid")
        container.rmdir()


def _cleanup_stale_stages(repo: Path, state: Path) -> None:
    for candidate in sorted(state.glob("stage-*")):
        if candidate.is_symlink() or not candidate.is_dir():
            raise PublicationError("evidence publication state is invalid")
        marker_path = candidate / STAGE_MARKER
        if not os.path.lexists(marker_path):
            temporary_markers = list(candidate.glob(f".{STAGE_MARKER}.*.tmp"))
            if any(
                path.is_symlink() or not path.is_file() for path in temporary_markers
            ):
                raise PublicationError("evidence publication state is invalid")
            if {entry for entry in candidate.iterdir()} != set(temporary_markers):
                raise PublicationError("evidence publication state is invalid")
            for temporary in temporary_markers:
                temporary.unlink()
            candidate.rmdir()
            continue
        marker = _read_json_object(marker_path)
        if set(marker) != {
            "schema_version",
            "parent_pid",
            "parent_start",
            "child_pid",
            "child_start",
            "nonce",
            "worktree_device",
            "worktree_inode",
        }:
            raise PublicationError("evidence publication state is invalid")
        if (
            marker["schema_version"] != STAGE_SCHEMA
            or not isinstance(marker["parent_pid"], int)
            or isinstance(marker["parent_pid"], bool)
            or marker["parent_pid"] <= 0
            or not isinstance(marker["child_pid"], int)
            or isinstance(marker["child_pid"], bool)
            or marker["child_pid"] < 0
            or not isinstance(marker["nonce"], str)
            or len(marker["nonce"]) != 32
            or not set(marker["nonce"]) <= set("0123456789abcdef")
            or (
                marker["worktree_device"] is not None
                and (
                    not isinstance(marker["worktree_device"], int)
                    or isinstance(marker["worktree_device"], bool)
                )
            )
            or (
                marker["worktree_inode"] is not None
                and (
                    not isinstance(marker["worktree_inode"], int)
                    or isinstance(marker["worktree_inode"], bool)
                )
            )
            or (
                marker["parent_start"] is not None
                and (
                    not isinstance(marker["parent_start"], int)
                    or isinstance(marker["parent_start"], bool)
                )
            )
            or (
                marker["child_start"] is not None
                and (
                    not isinstance(marker["child_start"], int)
                    or isinstance(marker["child_start"], bool)
                )
            )
        ):
            raise PublicationError("evidence publication state is invalid")
        if _process_identity_is_alive(marker["parent_pid"], marker["parent_start"]):
            continue
        child_pid = marker["child_pid"]
        if child_pid > 0:
            child_start = marker["child_start"]
            if (
                not isinstance(child_start, int)
                or isinstance(child_start, bool)
                or child_start <= 0
            ):
                raise PublicationError("evidence publication state is invalid")
            _kill_session_members(
                child_pid,
                expected_leader_start=child_start,
            )
        _remove_stage(repo, candidate)
    _fsync_directory(state)


def _fallback_ignore(root: Path):
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored_names = {
            ".git",
            ".venv",
            ".pytest_cache",
            ".ruff_cache",
            "__pycache__",
            ".agents",
            ".codex",
            "build",
            "dist",
            "week-logs",
        }
        ignored: set[str] = set()
        relative_directory = Path(directory).relative_to(root)
        for name in names:
            if name in ignored_names or name.endswith((".pyc", ".egg-info")):
                ignored.add(name)
            elif name == ".env" or (
                name.startswith(".env.") and name != ".env.example"
            ):
                ignored.add(name)
            elif relative_directory.name == "artifacts" and name in {
                "private",
                "local",
            }:
                ignored.add(name)
            elif relative_directory == Path(".agent-guard/evidence"):
                if name not in EVIDENCE_FILENAMES:
                    ignored.add(name)
            elif relative_directory == Path(".agent-policy/evidence"):
                if name != ARTIFACTS[2][1].name:
                    ignored.add(name)
        return ignored

    return ignore


def _safe_relative_path(raw: str) -> Path:
    relative = Path(raw)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise PublicationError("working-tree staging failed")
    return relative


def _overlay_git_working_tree(repo: Path, worktree: Path) -> None:
    git_environment = _isolated_git_environment()
    intent_visible = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "diff",
            "--cached",
            "--ita-visible-in-index",
            "--name-only",
            "--no-renames",
            "-z",
        ],
        env=git_environment,
        capture_output=True,
        check=False,
    )
    intent_hidden = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "diff",
            "--cached",
            "--ita-invisible-in-index",
            "--name-only",
            "--no-renames",
            "-z",
        ],
        env=git_environment,
        capture_output=True,
        check=False,
    )
    if intent_visible.returncode != 0 or intent_hidden.returncode != 0:
        raise PublicationError("working-tree staging failed")
    visible_paths = {path for path in intent_visible.stdout.split(b"\0") if path}
    hidden_paths = {path for path in intent_hidden.stdout.split(b"\0") if path}
    if visible_paths - hidden_paths:
        raise PublicationError(
            "working-tree staging does not support intent-to-add entries"
        )
    staged = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--stage", "-z"],
        env=git_environment,
        capture_output=True,
        check=False,
    )
    if staged.returncode != 0:
        raise PublicationError("working-tree staging failed")
    records = [record for record in staged.stdout.split(b"\0") if record]
    if any(record.startswith(b"160000 ") for record in records):
        raise PublicationError("working-tree staging does not support Git submodules")
    for record in records:
        metadata, separator, _path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise PublicationError("working-tree staging failed")
        if fields[1] and not fields[1].strip(b"0"):
            raise PublicationError(
                "working-tree staging does not support intent-to-add entries"
            )
    emptied = subprocess.run(
        ["git", "-C", str(worktree), "read-tree", "--empty"],
        env=git_environment,
        capture_output=True,
        check=False,
    )
    if emptied.returncode != 0:
        raise PublicationError("working-tree staging failed")
    indexed = subprocess.run(
        ["git", "-C", str(worktree), "update-index", "-z", "--index-info"],
        env=git_environment,
        input=staged.stdout,
        capture_output=True,
        check=False,
    )
    if indexed.returncode != 0:
        raise PublicationError("working-tree staging failed")
    listing = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        env=git_environment,
        capture_output=True,
        check=False,
    )
    if listing.returncode != 0:
        raise PublicationError("working-tree staging failed")
    try:
        entries = [
            entry for entry in listing.stdout.decode("utf-8").split("\0") if entry
        ]
    except UnicodeDecodeError as exc:
        raise PublicationError("working-tree staging failed") from exc
    for raw_relative in entries:
        relative = _safe_relative_path(raw_relative)
        source = repo / relative
        destination = worktree / relative
        if not os.path.lexists(source):
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            os.symlink(os.readlink(source), destination)
        elif source.is_file():
            shutil.copy2(source, destination)
        else:
            raise PublicationError("working-tree staging failed")


def _prepare_stage(repo: Path, state: Path) -> tuple[Path, Path, str]:
    container = Path(tempfile.mkdtemp(prefix="stage-", dir=state))
    os.chmod(container, 0o700)
    nonce = uuid.uuid4().hex
    marker_path = container / STAGE_MARKER
    _replace_json_durable(
        marker_path,
        {
            "schema_version": STAGE_SCHEMA,
            "parent_pid": os.getpid(),
            "parent_start": _process_start_identity(os.getpid()),
            "child_pid": 0,
            "child_start": None,
            "nonce": nonce,
            "worktree_device": None,
            "worktree_inode": None,
        },
    )
    worktree = container / "worktree"
    try:
        git_environment = _isolated_git_environment()
        git_probe = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            env=git_environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if git_probe.returncode == 0 and git_probe.stdout.strip() == "true":
            added = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "add",
                    "--detach",
                    "--no-checkout",
                    str(worktree),
                    "HEAD",
                ],
                env=git_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            if added.returncode != 0:
                raise PublicationError("working-tree staging failed")
            _overlay_git_working_tree(repo, worktree)
        else:
            shutil.copytree(
                repo,
                worktree,
                symlinks=True,
                ignore=_fallback_ignore(repo),
            )
    except Exception:
        _remove_stage(repo, container)
        raise
    worktree_stat = worktree.stat()
    _replace_json_durable(
        marker_path,
        {
            "schema_version": STAGE_SCHEMA,
            "parent_pid": os.getpid(),
            "parent_start": _process_start_identity(os.getpid()),
            "child_pid": 0,
            "child_start": None,
            "nonce": nonce,
            "worktree_device": worktree_stat.st_dev,
            "worktree_inode": worktree_stat.st_ino,
        },
    )
    _fsync_directory(container)
    return container, worktree, nonce


def _selected_python(repo: Path) -> str:
    selected = os.environ.get("AGENT_SAFETY_EVIDENCE_PYTHON", sys.executable)
    selected_path = Path(selected)
    if not selected_path.is_absolute() and "/" in selected:
        return str((repo / selected_path).absolute())
    return selected


def _stage_marker_payload(
    *,
    worktree: Path,
    nonce: str,
    child_pid: int,
    child_start: int | None = None,
) -> dict[str, Any]:
    worktree_stat = worktree.stat()
    return {
        "schema_version": STAGE_SCHEMA,
        "parent_pid": os.getpid(),
        "parent_start": _process_start_identity(os.getpid()),
        "child_pid": child_pid,
        "child_start": child_start,
        "nonce": nonce,
        "worktree_device": worktree_stat.st_dev,
        "worktree_inode": worktree_stat.st_ino,
    }


def _wait_pinned_stopped(pinned: _PinnedProcess) -> None:
    while True:
        current = _read_process_identity(pinned.identity.pid)
        if (
            current is not None
            and current.start_identity == pinned.identity.start_identity
            and current.state == "D"
        ):
            _pidfd_send_signal(pinned.pidfd, signal.SIGKILL)
            raise PublicationError("staged process cleanup is incomplete")
        if (
            current is None
            or current.start_identity != pinned.identity.start_identity
            or current.state in {"T", "t", "Z", "X", "x"}
        ):
            return
        os.sched_yield()


def _wait_pinned_quiescent(pinned: _PinnedProcess) -> None:
    while True:
        current = _read_process_identity(pinned.identity.pid)
        if (
            current is None
            or current.start_identity != pinned.identity.start_identity
            or current.state in {"Z", "X", "x"}
        ):
            return
        if current.state == "D":
            raise PublicationError("staged process cleanup is incomplete")
        os.sched_yield()


def _kill_session_members(
    session_id: int,
    process: subprocess.Popen[Any] | None = None,
    leader: _PinnedProcess | None = None,
    *,
    expected_leader_start: int | None = None,
    termination: _TerminationController | None = None,
) -> None:
    pinned: dict[tuple[int, int], _PinnedProcess] = {}
    stopped: set[tuple[int, int]] = set()
    try:
        if process is not None and process.pid != session_id:
            raise PublicationError("safe process isolation is unavailable")
        if leader is not None:
            if (
                leader.identity.pid != session_id
                or leader.identity.session != session_id
            ):
                raise PublicationError("safe process isolation is unavailable")
            pinned[(session_id, leader.identity.start_identity)] = leader
        else:
            if expected_leader_start is None:
                raise PublicationError("safe process isolation is unavailable")
            current_leader = _read_process_identity(session_id)
            if current_leader is None:
                if _session_executable_member_pids(session_id):
                    raise PublicationError("staged process cleanup is incomplete")
                if process is not None:
                    process.wait()
                return
            if current_leader.start_identity != expected_leader_start:
                return
            if current_leader.session != session_id:
                raise PublicationError("safe process isolation is unavailable")
            candidate = _pin_session_member(session_id, session_id)
            if candidate is not None:
                pinned[(session_id, candidate.identity.start_identity)] = candidate
            else:
                if _session_executable_member_pids(session_id):
                    raise PublicationError("staged process cleanup is incomplete")
                if process is not None:
                    process.wait()
                return

        while True:
            for pid in _session_member_pids(session_id):
                identity = _read_process_identity(pid)
                if identity is None:
                    continue
                key = (identity.pid, identity.start_identity)
                if key in pinned:
                    continue
                candidate = _pin_session_member(pid, session_id)
                if candidate is not None:
                    pinned[key] = candidate
            for key, candidate in pinned.items():
                if key in stopped:
                    continue
                _pidfd_send_signal(candidate.pidfd, signal.SIGSTOP)
                stopped.add(key)
            for candidate in pinned.values():
                _wait_pinned_stopped(candidate)

            current_keys: set[tuple[int, int]] = set()
            for pid in _session_member_pids(session_id):
                identity = _read_process_identity(pid)
                if identity is not None:
                    current_keys.add((identity.pid, identity.start_identity))
            if current_keys <= pinned.keys():
                break

        _pause_once_for_test("during-session-cleanup", termination)
        for candidate in sorted(
            pinned.values(),
            key=lambda item: item.identity.pid == session_id,
        ):
            _pidfd_send_signal(candidate.pidfd, signal.SIGKILL)
        if process is not None:
            process.wait()
        for candidate in pinned.values():
            _wait_pinned_quiescent(candidate)
    finally:
        for candidate in pinned.values():
            os.close(candidate.pidfd)


def _kill_process_session(
    process: subprocess.Popen[Any],
    leader: _PinnedProcess | None = None,
    *,
    expected_leader_start: int | None = None,
    termination: _TerminationController | None = None,
) -> None:
    _kill_session_members(
        process.pid,
        process,
        leader,
        expected_leader_start=expected_leader_start,
        termination=termination,
    )


def _run_staged_demo(
    repo: Path,
    container: Path,
    worktree: Path,
    nonce: str,
    termination: _TerminationController,
) -> int:
    _require_pidfd_support()
    marker_path = container / STAGE_MARKER
    environment = os.environ.copy()
    environment["AGENT_SAFETY_EVIDENCE_STAGE_CONTAINER"] = str(container)
    environment["AGENT_SAFETY_EVIDENCE_STAGE_NONCE"] = nonce
    environment["PYTHON"] = _selected_python(repo)
    runtime = container / STAGE_RUNTIME
    runtime.mkdir(mode=0o700)
    for name in ("TMPDIR", "TEMP", "TMP"):
        environment[name] = str(runtime)
    read_gate, write_gate = os.pipe()
    environment["AGENT_SAFETY_EVIDENCE_GATE_FD"] = str(read_gate)
    process: subprocess.Popen[bytes] | None = None
    leader: _PinnedProcess | None = None
    cleanup_attempted = False
    try:
        process = subprocess.Popen(
            [
                "bash",
                "-c",
                (
                    'IFS= read -r _ <&"$AGENT_SAFETY_EVIDENCE_GATE_FD" || exit 1; '
                    "exec bash scripts/run_demo.sh"
                ),
            ],
            cwd=worktree,
            env=environment,
            pass_fds=(read_gate,),
            start_new_session=True,
        )
        leader = _pin_session_member(process.pid, process.pid)
        if leader is None:
            raise PublicationError("safe process isolation is unavailable")
        os.close(read_gate)
        read_gate = -1
        _replace_json_durable(
            marker_path,
            _stage_marker_payload(
                worktree=worktree,
                nonce=nonce,
                child_pid=process.pid,
                child_start=leader.identity.start_identity,
            ),
        )
        termination.raise_if_pending()
        os.write(write_gate, b"\n")
        os.close(write_gate)
        write_gate = -1
        if termination.wait_for_process(leader.pidfd):
            cleanup_attempted = True
            try:
                _kill_process_session(process, leader, termination=termination)
            finally:
                leader = None
            return_code = termination.exit_code
        else:
            cleanup_attempted = True
            try:
                _kill_process_session(process, leader, termination=termination)
            finally:
                leader = None
            if process.returncode is None:
                raise PublicationError("staged process cleanup is incomplete")
            return_code = process.returncode
    except _TerminationRequested:
        if process is not None:
            cleanup_attempted = True
            try:
                _kill_process_session(process, leader, termination=termination)
            finally:
                leader = None
        return_code = termination.exit_code
    except BaseException:
        if process is not None and not cleanup_attempted:
            try:
                _kill_process_session(process, leader, termination=termination)
            finally:
                leader = None
        raise
    finally:
        if read_gate >= 0:
            os.close(read_gate)
        if write_gate >= 0:
            os.close(write_gate)
        if leader is not None:
            os.close(leader.pidfd)
    _replace_json_durable(
        marker_path,
        _stage_marker_payload(
            worktree=worktree, nonce=nonce, child_pid=0
        ),
    )
    return return_code


def _verify_stage(repo: Path, container: Path, nonce: str) -> int:
    if container.is_symlink() or not container.is_dir():
        raise PublicationError("evidence staging authorization failed")
    marker = _read_json_object(container / STAGE_MARKER)
    if set(marker) != {
        "schema_version",
        "parent_pid",
        "parent_start",
        "child_pid",
        "child_start",
        "nonce",
        "worktree_device",
        "worktree_inode",
    }:
        raise PublicationError("evidence staging authorization failed")
    repo_stat = repo.stat()
    if (
        marker["schema_version"] != STAGE_SCHEMA
        or marker["nonce"] != nonce
        or marker["child_pid"] != os.getppid()
        or marker["child_start"] != _process_start_identity(os.getppid())
        or marker["worktree_device"] != repo_stat.st_dev
        or marker["worktree_inode"] != repo_stat.st_ino
        or not _process_identity_is_alive(
            marker["parent_pid"], marker["parent_start"]
        )
        or repo.parent != container
        or repo.name != "worktree"
    ):
        raise PublicationError("evidence staging authorization failed")
    return 0


def _check_no_symlink_components(root: Path, relative: Path) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current) and current.is_symlink():
            raise PublicationError("evidence publication input is invalid")


def _inspect_bundle(root: Path, *, require_present: bool) -> bool:
    evidence_dir = root / ".agent-guard/evidence"
    for _role, relative in ARTIFACTS:
        _check_no_symlink_components(root, relative)
    if os.path.lexists(evidence_dir):
        if evidence_dir.is_symlink() or not evidence_dir.is_dir():
            raise PublicationError("evidence publication input is invalid")
        entries = list(evidence_dir.iterdir())
        if {entry.name for entry in entries} - EVIDENCE_FILENAMES:
            raise PublicationError("evidence publication input is invalid")
        if any(entry.is_symlink() or not entry.is_file() for entry in entries):
            raise PublicationError("evidence publication input is invalid")
    present: list[bool] = []
    for _role, relative in ARTIFACTS:
        path = root / relative
        exists = os.path.lexists(path)
        if exists and (path.is_symlink() or not path.is_file()):
            raise PublicationError("evidence publication input is invalid")
        present.append(exists)
    if any(present) and not all(present):
        raise PublicationError("evidence publication set is incomplete")
    if require_present and not all(present):
        raise PublicationError("evidence publication set is incomplete")
    return all(present)


def _inspect_live_bundle(live: _LiveArtifacts, *, require_present: bool) -> bool:
    _assert_live_bindings(live)
    try:
        names = set(os.listdir(live.guard_evidence.fd))
    except OSError as exc:
        raise PublicationError("evidence publication input is invalid") from exc
    if names - EVIDENCE_FILENAMES:
        raise PublicationError("evidence publication input is invalid")
    present = [_live_stat(artifact) is not None for artifact in live.artifacts]
    if any(present) and not all(present):
        raise PublicationError("evidence publication set is incomplete")
    if require_present and not all(present):
        raise PublicationError("evidence publication set is incomplete")
    return all(present)


def _verify_same_filesystem(live: _LiveArtifacts, state: Path, stage: Path) -> None:
    _assert_live_bindings(live)
    devices = {live.repo.device, state.stat().st_dev, stage.stat().st_dev}
    devices.update(directory.device for directory in live.directories)
    if len(devices) != 1:
        raise PublicationError("evidence publication requires one local filesystem")


def _snapshot_live_bundle(live: _LiveArtifacts, destination_root: Path) -> None:
    _inspect_live_bundle(live, require_present=True)
    for artifact in live.artifacts:
        destination = destination_root / artifact.relative
        _copy_live_to_private_durable(artifact, destination)
    _assert_live_bindings(live)


def _consumer_command(repo: Path, snapshot: Path, consumer: str) -> list[str]:
    evidence_dir = snapshot / ".agent-guard/evidence"
    report = snapshot / ARTIFACTS[0][1]
    event = snapshot / ARTIFACTS[2][1]
    common = [
        "--repo-root",
        str(snapshot),
        "--evidence-dir",
        str(evidence_dir),
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        str(report),
    ]
    if consumer == "example":
        return [
            _selected_python(repo),
            str(repo / "examples/evidence_consumer.py"),
            *common,
        ]
    if consumer == "packaged":
        return [_selected_python(repo), "-m", "agent_guard.consumer", *common]
    raise PublicationError("evidence consumer selection is invalid")


def _validate_snapshot(repo: Path, snapshot: Path) -> None:
    for consumer in ("example", "packaged"):
        result = subprocess.run(
            _consumer_command(repo, snapshot, consumer),
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise PublicationError(
                f"published evidence failed {consumer} consumer validation "
                f"(exit {result.returncode})"
            )


def _transaction_directory(state: Path) -> Path:
    return state / "transaction"


def _rollback_temporary(relative: Path, role: str) -> Path:
    return relative.parent / f".{relative.name}.{role}.rollback.tmp"


def _cleanup_preparation_directory(preparation: Path) -> None:
    if preparation.is_symlink() or not preparation.is_dir():
        raise PublicationError("evidence publication state is invalid")
    allowed_root = {TRANSACTION_MARKER, JOURNAL_NAME, "old", "new"}
    for entry in preparation.iterdir():
        if entry.name.startswith(f".{TRANSACTION_MARKER}.") and entry.name.endswith(
            ".tmp"
        ):
            if entry.is_symlink() or not entry.is_file():
                raise PublicationError("evidence publication state is invalid")
            continue
        if entry.name.startswith(f".{JOURNAL_NAME}.") and entry.name.endswith(".tmp"):
            if entry.is_symlink() or not entry.is_file():
                raise PublicationError("evidence publication state is invalid")
            continue
        if entry.name not in allowed_root:
            raise PublicationError("evidence publication state is invalid")
        if entry.name in {"old", "new"}:
            if entry.is_symlink() or not entry.is_dir():
                raise PublicationError("evidence publication state is invalid")
            for child in entry.iterdir():
                is_role = child.name in {role for role, _relative in ARTIFACTS}
                is_temporary = child.name.startswith(".") and child.name.endswith(".tmp")
                if (
                    child.is_symlink()
                    or not child.is_file()
                    or not (is_role or is_temporary)
                ):
                    raise PublicationError("evidence publication state is invalid")
        elif entry.is_symlink() or not entry.is_file():
            raise PublicationError("evidence publication state is invalid")
    marker = preparation / TRANSACTION_MARKER
    if os.path.lexists(marker) and _read_json_object(marker) != {
        "schema_version": TRANSACTION_SCHEMA
    }:
        raise PublicationError("evidence publication state is invalid")
    shutil.rmtree(preparation)


def _cleanup_stale_preparations(state: Path) -> None:
    for preparation in sorted(state.glob(f"{TRANSACTION_PREPARATION_PREFIX}*")):
        _cleanup_preparation_directory(preparation)
    _fsync_directory(state)


def _validate_journal(live: _LiveArtifacts, transaction: Path) -> dict[str, Any]:
    journal = _read_json_object(transaction / JOURNAL_NAME)
    if set(journal) != {"schema_version", "root_device", "root_inode", "artifacts"}:
        raise PublicationError("evidence publication state is invalid")
    if (
        journal["schema_version"] != JOURNAL_SCHEMA
        or journal["root_device"] != live.repo.device
        or journal["root_inode"] != live.repo.inode
        or not isinstance(journal["artifacts"], list)
        or len(journal["artifacts"]) != len(ARTIFACTS)
    ):
        raise PublicationError("evidence publication state is invalid")
    for actual, (role, relative) in zip(journal["artifacts"], ARTIFACTS, strict=True):
        if not isinstance(actual, dict) or set(actual) != {
            "role",
            "path",
            "old_present",
            "old_digest",
            "old_mode",
            "new_digest",
            "rollback_temp",
        }:
            raise PublicationError("evidence publication state is invalid")
        if (
            actual["role"] != role
            or actual["path"] != relative.as_posix()
            or actual["rollback_temp"]
            != _rollback_temporary(relative, role).as_posix()
        ):
            raise PublicationError("evidence publication state is invalid")
        if not isinstance(actual["old_present"], bool):
            raise PublicationError("evidence publication state is invalid")
        digests = (actual["old_digest"], actual["new_digest"])
        digest_alphabet = set("abcdefghijklmnopqrstuvwxyz234567")
        if (
            not isinstance(digests[1], str)
            or len(digests[1]) != 53
            or not digests[1].startswith("b")
            or not set(digests[1][1:]) <= digest_alphabet
        ):
            raise PublicationError("evidence publication state is invalid")
        if actual["old_present"]:
            if (
                not isinstance(digests[0], str)
                or len(digests[0]) != 53
                or not digests[0].startswith("b")
                or not set(digests[0][1:]) <= digest_alphabet
            ):
                raise PublicationError("evidence publication state is invalid")
            if (
                not isinstance(actual["old_mode"], int)
                or isinstance(actual["old_mode"], bool)
                or not 0 <= actual["old_mode"] <= 0o777
            ):
                raise PublicationError("evidence publication state is invalid")
        elif digests[0] is not None or actual["old_mode"] is not None:
            raise PublicationError("evidence publication state is invalid")
    return journal


def _cleanup_committed_transaction(state: Path, transaction: Path) -> None:
    if os.path.lexists(transaction / JOURNAL_NAME):
        raise PublicationError("evidence publication state is invalid")
    marker = transaction / TRANSACTION_MARKER
    known_temps = [
        *transaction.glob(f".{TRANSACTION_MARKER}.*.tmp"),
        *transaction.glob(f".{JOURNAL_NAME}.*.tmp"),
    ]
    if any(path.is_symlink() or not path.is_file() for path in known_temps):
        raise PublicationError("evidence publication state is invalid")
    if not os.path.lexists(marker):
        if {entry for entry in transaction.iterdir()} != set(known_temps):
            raise PublicationError("evidence publication state is invalid")
        for temporary in known_temps:
            temporary.unlink()
        transaction.rmdir()
        _fsync_directory(state)
        return
    if _read_json_object(marker) != {"schema_version": TRANSACTION_SCHEMA}:
        raise PublicationError("evidence publication state is invalid")
    for directory_name in ("new", "old"):
        directory = transaction / directory_name
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise PublicationError("evidence publication state is invalid")
            unknown = {entry.name for entry in directory.iterdir()} - {
                role for role, _ in ARTIFACTS
            }
            if unknown:
                raise PublicationError("evidence publication state is invalid")
            shutil.rmtree(directory)
    _fsync_directory(transaction)
    for temporary in known_temps:
        temporary.unlink()
    marker.unlink()
    _pause_for_test("after-transaction-marker-unlink")
    _fsync_directory(transaction)
    if any(transaction.iterdir()):
        raise PublicationError("evidence publication state is invalid")
    transaction.rmdir()
    _fsync_directory(state)


def _recover_transaction(live: _LiveArtifacts, state: Path) -> None:
    transaction = _transaction_directory(state)
    if not os.path.lexists(transaction):
        return
    if transaction.is_symlink() or not transaction.is_dir():
        raise PublicationError("evidence publication state is invalid")
    marker_path = transaction / TRANSACTION_MARKER
    journal_path = transaction / JOURNAL_NAME
    if not os.path.lexists(marker_path):
        if os.path.lexists(journal_path):
            raise PublicationError("evidence publication state is invalid")
        _cleanup_committed_transaction(state, transaction)
        return
    marker = _read_json_object(marker_path)
    if marker != {"schema_version": TRANSACTION_SCHEMA}:
        raise PublicationError("evidence publication state is invalid")
    if not os.path.lexists(journal_path):
        _cleanup_committed_transaction(state, transaction)
        return
    journal = _validate_journal(live, transaction)
    artifacts_by_role = {entry["role"]: entry for entry in journal["artifacts"]}
    live_by_role = live.by_role()
    _assert_live_bindings(live)
    for role, _relative in reversed(ARTIFACTS):
        entry = artifacts_by_role[role]
        artifact = live_by_role[role]
        rollback_temporary = Path(entry["rollback_temp"]).name
        _remove_live_temporary(artifact, rollback_temporary)
        if entry["old_present"]:
            backup = transaction / "old" / role
            if _digest(backup) != entry["old_digest"]:
                raise PublicationError("evidence publication state is invalid")
            _copy_private_to_live_durable(
                backup,
                artifact,
                mode=entry["old_mode"],
                temporary_name=rollback_temporary,
                pause_point="during-rollback-copy",
            )
        else:
            _unlink_live_regular(artifact)
    for role, _relative in ARTIFACTS:
        entry = artifacts_by_role[role]
        artifact = live_by_role[role]
        if entry["old_present"]:
            if _digest_live(artifact) != entry["old_digest"]:
                raise PublicationError("evidence publication recovery failed")
        elif _live_stat(artifact) is not None:
            raise PublicationError("evidence publication recovery failed")
    _assert_live_bindings(live)
    journal_path.unlink()
    _fsync_directory(transaction)
    _cleanup_committed_transaction(state, transaction)


def _begin_transaction(
    live: _LiveArtifacts, state: Path, stage: Path
) -> tuple[Path, dict[str, Any]]:
    transaction = _transaction_directory(state)
    if os.path.lexists(transaction):
        raise PublicationError("evidence publication state is invalid")
    preparation = Path(
        tempfile.mkdtemp(prefix=TRANSACTION_PREPARATION_PREFIX, dir=state)
    )
    os.chmod(preparation, 0o700)
    try:
        _pause_for_test("after-preparation-directory")
        _replace_json_durable(
            preparation / TRANSACTION_MARKER,
            {"schema_version": TRANSACTION_SCHEMA},
        )
        (preparation / "old").mkdir(mode=0o700)
        (preparation / "new").mkdir(mode=0o700)
        _fsync_directory(preparation)
        old_present = _inspect_live_bundle(live, require_present=False)
        _inspect_bundle(stage, require_present=True)
        live_by_role = live.by_role()
        entries: list[dict[str, Any]] = []
        for index, (role, relative) in enumerate(ARTIFACTS):
            candidate = stage / relative
            candidate_mode = stat.S_IMODE(os.lstat(candidate).st_mode)
            if candidate_mode > 0o777:
                raise PublicationError("evidence publication file mode is invalid")
            new_copy = preparation / "new" / role
            _copy_file_durable(
                candidate,
                new_copy,
                pause_point="during-preparation-copy" if index == 0 else None,
            )
            old_digest: str | None = None
            old_mode: int | None = None
            if old_present:
                metadata = _live_stat(live_by_role[role])
                if metadata is None:
                    raise PublicationError("evidence publication set is incomplete")
                old_mode = stat.S_IMODE(metadata.st_mode)
                if old_mode > 0o777:
                    raise PublicationError("evidence publication file mode is invalid")
                backup = preparation / "old" / role
                _copy_live_to_private_durable(
                    live_by_role[role], backup, mode=0o400
                )
                os.chmod(backup, 0o400)
                old_digest = _digest(backup)
            entries.append(
                {
                    "role": role,
                    "path": relative.as_posix(),
                    "old_present": old_present,
                    "old_digest": old_digest,
                    "old_mode": old_mode,
                    "new_digest": _digest(new_copy),
                    "rollback_temp": _rollback_temporary(relative, role).as_posix(),
                }
            )
        _fsync_directory(preparation / "old")
        _fsync_directory(preparation / "new")
        journal = {
            "schema_version": JOURNAL_SCHEMA,
            "root_device": live.repo.device,
            "root_inode": live.repo.inode,
            "artifacts": entries,
        }
        _replace_json_durable(preparation / JOURNAL_NAME, journal)
        _fsync_directory(preparation)
        os.replace(preparation, transaction)
        _fsync_directory(state)
        return transaction, journal
    except BaseException:
        if preparation.exists():
            _cleanup_preparation_directory(preparation)
            _fsync_directory(state)
        raise


def _publish_transaction(
    live: _LiveArtifacts,
    state: Path,
    stage: Path,
    termination: _TerminationController,
) -> None:
    transaction, journal = _begin_transaction(live, state, stage)
    entries = {entry["role"]: entry for entry in journal["artifacts"]}
    live_by_role = live.by_role()
    try:
        termination.raise_if_pending()
        new_fd = os.open(transaction / "new", _directory_flags())
        try:
            for index, (role, _relative) in enumerate(ARTIFACTS):
                artifact = live_by_role[role]
                _assert_live_bindings(live)
                os.replace(
                    role,
                    artifact.name,
                    src_dir_fd=new_fd,
                    dst_dir_fd=artifact.directory.fd,
                )
                destination_fd = _open_regular_at(
                    artifact.directory.fd, artifact.name
                )
                try:
                    os.fsync(destination_fd)
                finally:
                    os.close(destination_fd)
                os.fsync(new_fd)
                os.fsync(artifact.directory.fd)
                if index == 0:
                    _pause_for_test("after-first-replace", termination)
                termination.raise_if_pending()
        finally:
            os.close(new_fd)
        for role, _relative in ARTIFACTS:
            if _digest_live(live_by_role[role]) != entries[role]["new_digest"]:
                raise PublicationError("evidence publication verification failed")
        with tempfile.TemporaryDirectory(
            prefix="agent-safety-evidence-snapshot-"
        ) as raw_snapshot:
            snapshot = Path(raw_snapshot)
            _snapshot_live_bundle(live, snapshot)
            _validate_snapshot(live.repo_path, snapshot)
        _assert_live_bindings(live)
        termination.raise_if_pending()
        with termination.commit_linearization():
            (transaction / JOURNAL_NAME).unlink()
            _fsync_directory(transaction)
        _cleanup_committed_transaction(state, transaction)
    except BaseException:
        if os.path.lexists(transaction / JOURNAL_NAME):
            _recover_transaction(live, state)
        raise


def _run(repo: Path) -> int:
    state = _ensure_state_directory(repo)
    with _publication_lock(state, blocking=False):
        _cleanup_stale_preparations(state)
        with _open_live_artifacts(repo, create_parents=True) as live:
            _recover_transaction(live, state)
            _cleanup_stale_stages(repo, state)
            container, stage, nonce = _prepare_stage(repo, state)
            result = 0
            stage_removable = False
            with _coalesced_termination() as termination:
                try:
                    result = _run_staged_demo(
                        repo, container, stage, nonce, termination
                    )
                    stage_removable = True
                    if result == 0 and termination.signal_number is None:
                        _inspect_bundle(stage, require_present=True)
                    if result == 0 and termination.signal_number is None:
                        _pause_for_test("before-publish", termination)
                    if result == 0 and termination.signal_number is None:
                        _verify_same_filesystem(live, state, stage)
                    if result == 0 and termination.signal_number is None:
                        _publish_transaction(live, state, stage, termination)
                except _TerminationRequested:
                    result = termination.exit_code
                finally:
                    if stage_removable:
                        _remove_stage(repo, container)
                    _fsync_directory(state)
                if termination.signal_number is not None:
                    print(termination.diagnostic, file=sys.stderr)
                    result = termination.exit_code
            return result


def _consume(repo: Path, consumer: str) -> int:
    state = _ensure_state_directory(repo)
    with tempfile.TemporaryDirectory(
        prefix="agent-safety-evidence-snapshot-"
    ) as raw_snapshot:
        snapshot = Path(raw_snapshot)
        with _publication_lock(state, blocking=False, reader=True):
            _cleanup_stale_preparations(state)
            with _open_live_artifacts(repo, create_parents=False) as live:
                _recover_transaction(live, state)
                _cleanup_stale_stages(repo, state)
                _snapshot_live_bundle(live, snapshot)
        result = subprocess.run(
            _consumer_command(repo, snapshot, consumer),
            cwd=repo,
            check=False,
        )
        return result.returncode


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish or consume the demo evidence snapshot"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--repo", required=True)
    consume_parser = subparsers.add_parser("consume")
    consume_parser.add_argument("--repo", required=True)
    consume_parser.add_argument(
        "--consumer", choices=("example", "packaged"), required=True
    )
    verify_parser = subparsers.add_parser("verify-stage")
    verify_parser.add_argument("--repo", required=True)
    verify_parser.add_argument("--container", required=True)
    verify_parser.add_argument("--nonce", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        repo = Path(args.repo).resolve(strict=True)
        if not repo.is_dir():
            raise PublicationError("evidence repository is invalid")
        if args.command == "run":
            return _run(repo)
        if args.command == "verify-stage":
            container = Path(args.container)
            if not container.is_absolute():
                raise PublicationError("evidence staging authorization failed")
            return _verify_stage(repo, container, args.nonce)
        return _consume(repo, args.consumer)
    except WriterBusy as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except PublicationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("evidence publication interrupted", file=sys.stderr)
        return 130
    except BaseException:
        print("evidence publication failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
