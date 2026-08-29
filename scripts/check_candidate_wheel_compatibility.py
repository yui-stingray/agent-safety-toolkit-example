#!/usr/bin/env python3
"""Exercise one or two candidate toolkit wheels in an isolated checkout."""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = Path("requirements/agent-safety-tools.txt")
SUPPORTED_DISTRIBUTIONS = frozenset({"yui-agent-guard", "yui-agent-policy"})
CANDIDATE_COMPATIBILITY_ENV = "AGENT_SAFETY_CANDIDATE_WHEEL_COMPATIBILITY"
PRIVATE_TEMP_PARENT = Path("/tmp")
WORKTREE_IGNORES = shutil.ignore_patterns(
    ".git",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    ".agent-safety-evidence-state",
)
_DISTRIBUTION_NORMALIZER = re.compile(r"[-_.]+")


class CompatibilityError(RuntimeError):
    """A public-safe failure from the candidate compatibility harness."""


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise CompatibilityError("candidate compatibility invocation is invalid")


@dataclass(frozen=True)
class Runtime:
    implementation: str
    version: tuple[int, int]
    system: str
    machine: str


@dataclass(frozen=True)
class CandidateWheel:
    distribution: str
    staged_path: Path


@dataclass(frozen=True)
class Command:
    stage: str
    argv: tuple[str, ...]


def _current_runtime() -> Runtime:
    return Runtime(
        implementation=sys.implementation.name,
        version=sys.version_info[:2],
        system=platform.system(),
        machine=platform.machine(),
    )


def _require_supported_runtime(runtime: Runtime) -> None:
    if (
        runtime.implementation != "cpython"
        or runtime.version != (3, 12)
        or runtime.system != "Linux"
        or runtime.machine != "x86_64"
    ):
        raise CompatibilityError(
            "candidate compatibility requires CPython 3.12 on Linux x86_64"
        )


def _canonicalize_distribution(value: str) -> str:
    return _DISTRIBUTION_NORMALIZER.sub("-", value).lower()


def _copy_regular_wheel(source: Path, destination: Path) -> None:
    if source.suffix != ".whl":
        raise CompatibilityError("candidate wheel input is invalid")
    try:
        source_status = os.lstat(source)
    except OSError:
        raise CompatibilityError("candidate wheel input is invalid") from None
    if stat.S_ISLNK(source_status.st_mode) or not stat.S_ISREG(source_status.st_mode):
        raise CompatibilityError("candidate wheel input is invalid")

    descriptor: int | None = None
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        source_status = os.fstat(descriptor)
        if not stat.S_ISREG(source_status.st_mode):
            raise CompatibilityError("candidate wheel input is invalid")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(descriptor, "rb") as source_file:
            descriptor = None
            with destination.open("xb") as destination_file:
                shutil.copyfileobj(source_file, destination_file)
                destination_file.flush()
                os.fsync(destination_file.fileno())
    except CompatibilityError:
        raise
    except OSError:
        raise CompatibilityError("candidate wheel input is invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _wheel_distribution(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_paths = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_paths) != 1:
                raise CompatibilityError("candidate wheel distribution is invalid")
            metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
    except CompatibilityError:
        raise
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile):
        raise CompatibilityError("candidate wheel distribution is invalid") from None

    names = metadata.get_all("Name")
    if not isinstance(names, list) or len(names) != 1 or not isinstance(names[0], str):
        raise CompatibilityError("candidate wheel distribution is invalid")
    distribution = _canonicalize_distribution(names[0].strip())
    if distribution not in SUPPORTED_DISTRIBUTIONS:
        raise CompatibilityError("candidate wheel distribution is invalid")
    return distribution


def stage_candidate_wheels(
    paths: Sequence[str | Path], destination: Path
) -> tuple[CandidateWheel, ...]:
    if not 1 <= len(paths) <= len(SUPPORTED_DISTRIBUTIONS):
        raise CompatibilityError("candidate wheel selection is invalid")

    candidates: list[CandidateWheel] = []
    for index, value in enumerate(paths, start=1):
        source = Path(value)
        staged_path = destination / str(index) / source.name
        _copy_regular_wheel(source, staged_path)
        candidates.append(
            CandidateWheel(
                distribution=_wheel_distribution(staged_path),
                staged_path=staged_path,
            )
        )

    if len({candidate.distribution for candidate in candidates}) != len(candidates):
        raise CompatibilityError("candidate wheel selection is invalid")
    return tuple(sorted(candidates, key=lambda candidate: candidate.distribution))


def _isolated_environment(temp_root: Path, venv: Path | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if (
            name.startswith("GIT_")
            or name.startswith("PIP_")
            or name.startswith("PYTHON")
            or name == "VIRTUAL_ENV"
            or name == CANDIDATE_COMPATIBILITY_ENV
        ):
            environment.pop(name, None)

    home = temp_root / "home"
    runtime = temp_root / "runtime"
    config = temp_root / "config"
    for directory in (home, runtime, config):
        directory.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "PATH": os.defpath,
            "TEMP": str(runtime),
            "TMP": str(runtime),
            "TMPDIR": str(runtime),
            "XDG_CONFIG_HOME": str(config),
        }
    )
    if venv is not None:
        python = venv / "bin" / "python"
        environment.update(
            {
                "PATH": os.pathsep.join((str(venv / "bin"), os.defpath)),
                "PYTHON": str(python),
                "VIRTUAL_ENV": str(venv),
            }
        )
    return environment


def _read_committed_lock(source: Path, environment: dict[str, str]) -> bytes:
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{LOCK_PATH.as_posix()}"],
            cwd=source,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        raise CompatibilityError("committed dependency lock is unavailable") from None
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise CompatibilityError("committed dependency lock is unavailable")
    return result.stdout


def _copy_worktree(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(source, destination, ignore=WORKTREE_IGNORES)
    except (OSError, shutil.Error):
        raise CompatibilityError(
            "candidate compatibility failed during isolated toolkit copy"
        ) from None


def _write_committed_lock(worktree: Path, contents: bytes) -> None:
    destination = worktree / LOCK_PATH
    try:
        if destination.is_symlink() or not destination.is_file():
            raise CompatibilityError("committed dependency lock is unavailable")
        destination.write_bytes(contents)
    except CompatibilityError:
        raise
    except OSError:
        raise CompatibilityError("committed dependency lock is unavailable") from None


def _run_silent(
    stage: str, argv: Sequence[str], *, cwd: Path, env: dict[str, str]
) -> None:
    try:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        raise CompatibilityError(
            f"candidate compatibility failed during {stage}"
        ) from None
    if result.returncode != 0:
        raise CompatibilityError(f"candidate compatibility failed during {stage}")


def _initialize_isolated_worktree(worktree: Path, environment: dict[str, str]) -> None:
    _run_silent(
        "isolated toolkit initialization",
        ("git", "init", "--quiet"),
        cwd=worktree,
        env=environment,
    )
    _run_silent(
        "isolated toolkit staging",
        ("git", "add", "--all"),
        cwd=worktree,
        env=environment,
    )
    _run_silent(
        "isolated toolkit baseline commit",
        (
            "git",
            "-c",
            "user.name=Candidate Wheel Check",
            "-c",
            "user.email=candidate-wheel-check@example.invalid",
            "-c",
            f"core.hooksPath={os.devnull}",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "candidate compatibility baseline",
        ),
        cwd=worktree,
        env=environment,
    )


def _create_venv(venv: Path, environment: dict[str, str]) -> Path:
    _run_silent(
        "isolated CPython environment creation",
        (sys.executable, "-m", "venv", str(venv)),
        cwd=venv.parent,
        env=environment,
    )
    python = venv / "bin" / "python"
    if not python.is_file():
        raise CompatibilityError(
            "candidate compatibility failed during isolated CPython "
            "environment creation"
        )
    return python


def execution_commands(
    python: Path, worktree: Path, candidates: Sequence[CandidateWheel]
) -> tuple[Command, ...]:
    pip = (
        str(python),
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
    )
    return (
        Command(
            "committed hash lock installation",
            (*pip, "install", "--require-hashes", "-r", str(worktree / LOCK_PATH)),
        ),
        Command(
            "candidate wheel overlay",
            (
                *pip,
                "install",
                "--no-index",
                "--no-deps",
                "--force-reinstall",
                *(str(candidate.staged_path) for candidate in candidates),
            ),
        ),
        Command("pip dependency check", (*pip, "check")),
        Command("full toolkit pytest", (str(python), "-m", "pytest", "-q")),
        Command("toolkit demo", ("bash", "scripts/run_demo.sh")),
        Command(
            "example snapshot consumer",
            (
                str(python),
                "scripts/evidence_publication.py",
                "consume",
                "--repo",
                ".",
                "--consumer",
                "example",
            ),
        ),
        Command(
            "packaged snapshot consumer",
            (
                str(python),
                "scripts/evidence_publication.py",
                "consume",
                "--repo",
                ".",
                "--consumer",
                "packaged",
            ),
        ),
    )


def run_compatibility(
    wheel_paths: Sequence[str | Path],
    *,
    root: Path = ROOT,
    runtime: Runtime | None = None,
) -> None:
    _require_supported_runtime(_current_runtime() if runtime is None else runtime)

    with tempfile.TemporaryDirectory(
        prefix="candidate-wheel-compatibility-",
        dir=PRIVATE_TEMP_PARENT,
    ) as directory:
        temp_root = Path(directory)
        bootstrap_environment = _isolated_environment(temp_root)
        candidates = stage_candidate_wheels(wheel_paths, temp_root / "candidates")
        lock_contents = _read_committed_lock(root, bootstrap_environment)
        worktree = temp_root / "toolkit"
        _copy_worktree(root, worktree)
        _write_committed_lock(worktree, lock_contents)
        _initialize_isolated_worktree(worktree, bootstrap_environment)
        python = _create_venv(temp_root / "venv", bootstrap_environment)
        command_environment = _isolated_environment(temp_root, temp_root / "venv")
        command_environment[CANDIDATE_COMPATIBILITY_ENV] = "1"
        for command in execution_commands(python, worktree, candidates):
            _run_silent(
                command.stage,
                command.argv,
                cwd=worktree,
                env=command_environment,
            )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _SanitizedArgumentParser(
        prog="candidate-wheel-compatibility",
        description=(
            "Run local candidate agent toolkit wheels through the isolated demo checks."
        ),
    )
    parser.add_argument(
        "--wheel",
        action="append",
        metavar="WHEEL",
        help=(
            "A local yui-agent-guard or yui-agent-policy wheel; provide once or twice."
        ),
    )
    args = parser.parse_args(argv)
    if not args.wheel:
        raise CompatibilityError("candidate wheel selection is invalid")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        run_compatibility(args.wheel)
    except CompatibilityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("candidate compatibility check failed", file=sys.stderr)
        return 1
    print("candidate wheel compatibility check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
