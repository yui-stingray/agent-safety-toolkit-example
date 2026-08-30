from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from scripts import check_candidate_wheel_compatibility as compatibility


def write_wheel(path: Path, distribution: str) -> Path:
    dist_info = f"{distribution.replace('-', '_')}-1.0.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n",
        )
    return path


def supported_runtime() -> compatibility.Runtime:
    return compatibility.Runtime("cpython", (3, 12), "Linux", "x86_64")


def test_candidate_state_uses_native_linux_temp_not_inherited_temp() -> None:
    assert compatibility.PRIVATE_TEMP_PARENT == Path("/tmp")


def test_stage_candidate_wheels_accepts_one_or_both_supported_distributions(
    tmp_path: Path,
) -> None:
    guard = write_wheel(tmp_path / "guard.whl", "yui-agent-guard")
    policy = write_wheel(tmp_path / "policy.whl", "yui_agent_policy")

    guard_only = compatibility.stage_candidate_wheels(
        [guard], tmp_path / "guard-only"
    )
    policy_only = compatibility.stage_candidate_wheels(
        [policy], tmp_path / "policy-only"
    )
    both = compatibility.stage_candidate_wheels([policy, guard], tmp_path / "both")

    assert [candidate.distribution for candidate in guard_only] == ["yui-agent-guard"]
    assert [candidate.distribution for candidate in policy_only] == ["yui-agent-policy"]
    assert [candidate.distribution for candidate in both] == [
        "yui-agent-guard",
        "yui-agent-policy",
    ]
    assert all(candidate.staged_path.is_file() for candidate in both)
    assert all(not candidate.staged_path.is_symlink() for candidate in both)


@pytest.mark.parametrize(
    "paths",
    (
        (),
        (
            "yui-agent-guard",
            "yui-agent-guard",
            "yui-agent-policy",
        ),
    ),
)
def test_stage_candidate_wheels_rejects_missing_or_multiple_candidates(
    tmp_path: Path, paths: tuple[str, ...]
) -> None:
    wheels = [
        write_wheel(tmp_path / f"{index}.whl", name)
        for index, name in enumerate(paths)
    ]

    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate wheel selection is invalid",
    ):
        compatibility.stage_candidate_wheels(wheels, tmp_path / "staged")


def test_stage_candidate_wheels_rejects_duplicate_or_wrong_distribution(
    tmp_path: Path,
) -> None:
    guard = write_wheel(tmp_path / "guard.whl", "yui-agent-guard")
    duplicate = write_wheel(tmp_path / "duplicate.whl", "yui_agent_guard")
    wrong = write_wheel(tmp_path / "wrong.whl", "private-distribution-marker")

    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate wheel selection is invalid",
    ):
        compatibility.stage_candidate_wheels([guard, duplicate], tmp_path / "duplicate")
    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate wheel distribution is invalid",
    ):
        compatibility.stage_candidate_wheels([wrong], tmp_path / "wrong")


def test_stage_candidate_wheels_rejects_a_symlink(tmp_path: Path) -> None:
    wheel = write_wheel(tmp_path / "wheel.whl", "yui-agent-guard")
    symlink = tmp_path / "private-path-marker.whl"
    symlink.symlink_to(wheel)

    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate wheel input is invalid",
    ):
        compatibility.stage_candidate_wheels([symlink], tmp_path / "staged")


@pytest.mark.parametrize(
    "runtime",
    (
        compatibility.Runtime("pypy", (3, 12), "Linux", "x86_64"),
        compatibility.Runtime("cpython", (3, 11), "Linux", "x86_64"),
        compatibility.Runtime("cpython", (3, 12), "Darwin", "x86_64"),
        compatibility.Runtime("cpython", (3, 12), "Linux", "aarch64"),
    ),
)
def test_runtime_gate_fails_closed_outside_the_documented_target(
    runtime: compatibility.Runtime,
) -> None:
    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate compatibility requires CPython 3.12 on Linux x86_64",
    ):
        compatibility._require_supported_runtime(runtime)


def test_execution_commands_keep_candidate_sources_out_of_subprocess_arguments(
    tmp_path: Path,
) -> None:
    source_marker = tmp_path / "private-source-marker.whl"
    staged = tmp_path / "staged" / "guard.whl"
    commands = compatibility.execution_commands(
        tmp_path / "venv" / "bin" / "python",
        tmp_path / "toolkit",
        (compatibility.CandidateWheel("yui-agent-guard", staged),),
    )

    assert [command.stage for command in commands] == [
        "committed hash lock installation",
        "candidate wheel overlay",
        "pip dependency check",
        "candidate evidence warmup",
        "candidate evidence baseline staging",
        "candidate evidence baseline commit",
        "full toolkit pytest",
        "toolkit demo",
        "example snapshot consumer",
        "packaged snapshot consumer",
    ]
    assert "--require-hashes" in commands[0].argv
    assert "--no-index" in commands[1].argv
    assert "--no-deps" in commands[1].argv
    assert "--force-reinstall" in commands[1].argv
    assert commands[3].argv == ("bash", "scripts/run_demo.sh")
    assert commands[4].argv == (
        "git",
        "add",
        "--",
        *compatibility.CANDIDATE_EVIDENCE_PATHS,
    )
    assert "--allow-empty" in commands[5].argv
    assert commands[7].argv == ("bash", "scripts/run_demo.sh")
    assert commands[8].argv[-1] == "example"
    assert commands[9].argv[-1] == "packaged"
    assert str(source_marker) not in "\n".join(
        argument for command in commands for argument in command.argv
    )


def test_harness_uses_disposable_inputs_and_preserves_live_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    lock = source / "requirements" / "agent-safety-tools.txt"
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"live lock\n")
    evidence = source / ".agent-guard" / "evidence" / "live.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b'{"live": true}\n')
    guard = write_wheel(tmp_path / "private-guard-input.whl", "yui-agent-guard")
    policy = write_wheel(tmp_path / "private-policy-input.whl", "yui-agent-policy")
    calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    monkeypatch.setenv("PIP_INDEX_URL", "https://private.example.invalid/simple")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "private-pytest-plugin-marker")
    monkeypatch.setenv("PYTHONPATH", "private-pythonpath-marker")
    monkeypatch.setenv(
        compatibility.CANDIDATE_COMPATIBILITY_ENV,
        "untrusted-inherited-marker",
    )

    def fake_run(
        args: list[str], *, cwd: Path, env: dict[str, str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes | None]:
        command = tuple(str(argument) for argument in args)
        calls.append((command, Path(cwd), dict(env)))
        if command[:3] == (sys.executable, "-m", "venv"):
            python = Path(command[3]) / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")
        stdout = b"committed lock\n" if command[:2] == ("git", "show") else None
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    monkeypatch.setattr(compatibility.subprocess, "run", fake_run)

    compatibility.run_compatibility(
        [policy, guard], root=source, runtime=supported_runtime()
    )

    assert lock.read_bytes() == b"live lock\n"
    assert evidence.read_bytes() == b'{"live": true}\n'
    assert calls[0][0][:2] == ("git", "show")
    assert calls[0][1] == source
    subprocess_commands = [command for command, _cwd, _env in calls]
    assert any(
        command[1:4] == ("-m", "pip", "--isolated")
        for command in subprocess_commands
    )
    assert any(
        command[-2:] == ("--consumer", "example") for command in subprocess_commands
    )
    assert any(
        command[-2:] == ("--consumer", "packaged")
        for command in subprocess_commands
    )
    assert all(str(source) not in command for command in subprocess_commands[1:])
    assert all(
        str(guard) not in command and str(policy) not in command
        for command in subprocess_commands
    )
    pip_environments = [
        environment
        for command, _cwd, environment in calls
        if command[1:3] == ("-m", "pip")
    ]
    assert pip_environments
    assert all("PIP_INDEX_URL" not in environment for environment in pip_environments)
    assert all("PYTHONPATH" not in environment for environment in pip_environments)
    candidate_environments = [
        environment
        for _command, _cwd, environment in calls
        if compatibility.CANDIDATE_COMPATIBILITY_ENV in environment
    ]
    assert all(
        not any(name.startswith("PYTEST_") for name in environment)
        for environment in candidate_environments
    )
    assert len(candidate_environments) == len(
        compatibility.execution_commands(
            tmp_path / "venv" / "bin" / "python",
            tmp_path / "toolkit",
            (
                compatibility.CandidateWheel(
                    "yui-agent-guard",
                    tmp_path / "staged" / "guard.whl",
                ),
            ),
        )
    )
    assert all(
        environment[compatibility.CANDIDATE_COMPATIBILITY_ENV] == "1"
        for environment in candidate_environments
    )


def test_subprocess_failures_discard_untrusted_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "private-event-body-marker"
    captured: dict[str, object] = {}

    def failing_run(
        _args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            _args,
            1,
            stdout=f"https://private.example.invalid/{marker}",
            stderr=f"wheel hash {marker}",
        )

    monkeypatch.setattr(compatibility.subprocess, "run", failing_run)

    with pytest.raises(
        compatibility.CompatibilityError,
        match="candidate compatibility failed during toolkit demo",
    ) as error:
        compatibility._run_silent(
            "toolkit demo",
            ("bash", "scripts/run_demo.sh"),
            cwd=Path("/tmp"),
            env={},
        )

    assert marker not in str(error.value)
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL


def test_main_sanitizes_untrusted_invocation_and_candidate_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "private-input-marker"
    monkeypatch.setattr(compatibility, "_current_runtime", supported_runtime)

    invalid_invocation = compatibility.main([f"--{marker}"])
    invocation_output = capsys.readouterr()
    invalid_candidate = compatibility.main(
        ["--wheel", str(tmp_path / marker / "missing.whl")]
    )
    candidate_output = capsys.readouterr()

    assert invalid_invocation == 1
    assert invalid_candidate == 1
    assert invocation_output.out == ""
    assert invocation_output.err == "candidate compatibility invocation is invalid\n"
    assert candidate_output.out == ""
    assert candidate_output.err == "candidate wheel input is invalid\n"
    assert marker not in invocation_output.out + invocation_output.err
    assert marker not in candidate_output.out + candidate_output.err
