#!/usr/bin/env python3
"""Crash-consistent publication for the demo's three fixed evidence files.

This helper targets the repository's documented CPython 3.12 / Ubuntu Linux
local-filesystem contract.  It intentionally uses only advisory ``flock``,
``fsync``, and ordinary atomic rename semantics; it does not claim equivalent
durability on network or non-POSIX filesystems.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

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


class PublicationError(RuntimeError):
    """A sanitized publication failure."""


class WriterBusy(PublicationError):
    """Another writer currently owns the advisory lock."""


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
    except BaseException:
        if "temporary" in locals() and os.path.lexists(temporary):
            if temporary.is_symlink() or not temporary.is_file():
                raise PublicationError("evidence publication state is invalid")
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


def _pause_for_test(point: str) -> None:
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TESTING") != "1":
        return
    if os.environ.get("AGENT_SAFETY_EVIDENCE_TEST_PAUSE_AT") != point:
        return
    _create_test_marker("AGENT_SAFETY_EVIDENCE_TEST_MARKER")
    while True:
        signal.pause()


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
                raise WriterBusy("evidence publication is already in progress") from exc
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


def _process_start_identity(pid: int) -> int | None:
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
    if len(fields) <= 19 or not fields[19].isdigit():
        return None
    return int(fields[19])


def _process_identity_is_alive(pid: Any, start_identity: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if start_identity is not None and (
        not isinstance(start_identity, int) or isinstance(start_identity, bool)
    ):
        return False
    actual_start = _process_start_identity(pid)
    if start_identity is not None and actual_start is not None:
        return actual_start == start_identity
    return _pid_is_alive(pid)


def _remove_stage(repo: Path, container: Path) -> None:
    worktree = container / "worktree"
    if (repo / ".git").exists() and (worktree / ".git").exists():
        removed = subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
            text=True,
            capture_output=True,
            check=False,
        )
        if removed.returncode != 0:
            raise PublicationError("working-tree staging cleanup failed")
    if worktree.exists():
        shutil.rmtree(worktree)
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
            or not isinstance(marker["nonce"], str)
            or len(marker["nonce"]) != 32
            or not set(marker["nonce"]) <= set("0123456789abcdef")
            or (
                marker["worktree_device"] is not None
                and not isinstance(marker["worktree_device"], int)
            )
            or (
                marker["worktree_inode"] is not None
                and not isinstance(marker["worktree_inode"], int)
            )
            or (
                marker["parent_start"] is not None
                and not isinstance(marker["parent_start"], int)
            )
            or (
                marker["child_start"] is not None
                and not isinstance(marker["child_start"], int)
            )
        ):
            raise PublicationError("evidence publication state is invalid")
        if _process_identity_is_alive(
            marker["parent_pid"], marker["parent_start"]
        ) or _process_identity_is_alive(marker["child_pid"], marker["child_start"]):
            continue
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
    staged = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--stage", "-z"],
        capture_output=True,
        check=False,
    )
    if staged.returncode != 0:
        raise PublicationError("working-tree staging failed")
    if any(record.startswith(b"160000 ") for record in staged.stdout.split(b"\0")):
        raise PublicationError("working-tree staging does not support Git submodules")
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
        git_probe = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
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


def _selected_python() -> str:
    return os.environ.get("AGENT_SAFETY_EVIDENCE_PYTHON", sys.executable)


def _stage_marker_payload(
    *, container: Path, worktree: Path, nonce: str, child_pid: int
) -> dict[str, Any]:
    worktree_stat = worktree.stat()
    return {
        "schema_version": STAGE_SCHEMA,
        "parent_pid": os.getpid(),
        "parent_start": _process_start_identity(os.getpid()),
        "child_pid": child_pid,
        "child_start": _process_start_identity(child_pid),
        "nonce": nonce,
        "worktree_device": worktree_stat.st_dev,
        "worktree_inode": worktree_stat.st_ino,
    }


def _run_staged_demo(container: Path, worktree: Path, nonce: str) -> int:
    marker_path = container / STAGE_MARKER
    environment = os.environ.copy()
    environment["AGENT_SAFETY_EVIDENCE_STAGE_CONTAINER"] = str(container)
    environment["AGENT_SAFETY_EVIDENCE_STAGE_NONCE"] = nonce
    environment["PYTHON"] = _selected_python()
    read_gate, write_gate = os.pipe()
    environment["AGENT_SAFETY_EVIDENCE_GATE_FD"] = str(read_gate)
    try:
        process = subprocess.Popen(
            [
                "bash",
                "-c",
                'IFS= read -r _ <&"$AGENT_SAFETY_EVIDENCE_GATE_FD"; '
                "exec bash scripts/run_demo.sh",
            ],
            cwd=worktree,
            env=environment,
            pass_fds=(read_gate,),
        )
        os.close(read_gate)
        read_gate = -1
        try:
            _replace_json_durable(
                marker_path,
                _stage_marker_payload(
                    container=container,
                    worktree=worktree,
                    nonce=nonce,
                    child_pid=process.pid,
                ),
            )
            os.write(write_gate, b"\n")
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            os.close(write_gate)
            write_gate = -1
        return_code = process.wait()
    finally:
        if read_gate >= 0:
            os.close(read_gate)
        if write_gate >= 0:
            os.close(write_gate)
    _replace_json_durable(
        marker_path,
        _stage_marker_payload(
            container=container, worktree=worktree, nonce=nonce, child_pid=0
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
            _selected_python(),
            str(repo / "examples/evidence_consumer.py"),
            *common,
        ]
    if consumer == "packaged":
        return [_selected_python(), "-m", "agent_guard.consumer", *common]
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
            raise PublicationError("published evidence failed consumer validation")


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


def _publish_transaction(live: _LiveArtifacts, state: Path, stage: Path) -> None:
    transaction, journal = _begin_transaction(live, state, stage)
    entries = {entry["role"]: entry for entry in journal["artifacts"]}
    live_by_role = live.by_role()
    try:
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
                    _pause_for_test("after-first-replace")
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
            try:
                result = _run_staged_demo(container, stage, nonce)
                if result != 0:
                    return result
                _inspect_bundle(stage, require_present=True)
                _pause_for_test("before-publish")
                _verify_same_filesystem(live, state, stage)
                _publish_transaction(live, state, stage)
            finally:
                _remove_stage(repo, container)
                _fsync_directory(state)
    return 0


def _consume(repo: Path, consumer: str) -> int:
    state = _ensure_state_directory(repo)
    with tempfile.TemporaryDirectory(
        prefix="agent-safety-evidence-snapshot-"
    ) as raw_snapshot:
        snapshot = Path(raw_snapshot)
        with _publication_lock(state, blocking=True, reader=True):
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
    except BaseException:
        print("evidence publication failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
