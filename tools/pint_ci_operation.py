#!/usr/bin/env python3
"""Complete manual-only Pint CI launcher with bounded evidence capture.

The launcher creates two system-manager units through ``sudo -n
systemd-run``: a 768 MiB SDK unit and an exact 512 MiB parent unit for the
unchanged driver.  It uses explicit argv vectors and explicit child
environments, so hosted user-manager availability and nested shell quoting are
not assumptions.  Tests inject a controlled runner; this module never runs a
real unit in source verification.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Callable, Mapping

from public_contract_preflight import PublicContractError, verify_public_contract

MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
PARENT_SECONDS = 5100
JOB_SECONDS = 5400
SDK_SECONDS = 900
DRIVER_RELATIVE = "tools/pint_untreated_driver.py"


class OperationError(RuntimeError):
    """Raised for pre-effect launcher failures."""


@dataclass(frozen=True)
class LaunchConfig:
    workspace: Path
    runner_temp: Path
    run_id: str
    attempt: int
    uid: int
    gid: int
    now: int
    sdk_deadline: int
    parent_deadline: int
    job_deadline: int
    sdk_unit: str
    parent_unit: str
    evidence_dir: Path
    sdk_site: Path
    wheel_dir: Path
    docker_config: Path


def make_config(*, workspace: Path, runner_temp: Path, run_id: str, attempt: int, uid: int = 1000,
                gid: int = 1000, now: int | None = None) -> LaunchConfig:
    if attempt != 1:
        raise OperationError("automatic_attempt_refused")
    epoch = int(time.time() if now is None else now)
    evidence = runner_temp / "pint-original-evidence"
    return LaunchConfig(
        workspace=workspace,
        runner_temp=runner_temp,
        run_id=run_id,
        attempt=attempt,
        uid=uid,
        gid=gid,
        now=epoch,
        sdk_deadline=epoch + SDK_SECONDS,
        parent_deadline=epoch + PARENT_SECONDS,
        job_deadline=epoch + JOB_SECONDS,
        sdk_unit=f"glee-pint-sdk-{run_id}-{attempt}",
        parent_unit=f"glee-pint-parent-{run_id}-{attempt}",
        evidence_dir=evidence,
        sdk_site=runner_temp / "pint-original-sdk-site",
        wheel_dir=runner_temp / "pint-original-sdk-wheel",
        docker_config=runner_temp / "pint-original-docker-config",
    )


def _setenv(values: Mapping[str, str]) -> list[str]:
    return [f"--setenv={key}={value}" for key, value in values.items()]


def bounded_environment(config: LaunchConfig, *, pythonpath: Path | None = None) -> dict[str, str]:
    """Minimal explicit environment passed to a systemd child."""
    values = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": str(config.runner_temp / "pint-original-home"),
        "GITHUB_WORKSPACE": str(config.workspace),
        "RUNNER_TEMP": str(config.runner_temp),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "DOCKER_CONFIG": str(config.docker_config),
        "GLEE_PARENT_UNIT": config.parent_unit,
        "GLEE_PARENT_DEADLINE_EPOCH": str(config.parent_deadline),
        "GLEE_JOB_DEADLINE_EPOCH": str(config.job_deadline),
    }
    if pythonpath is not None:
        values["PYTHONPATH"] = str(pythonpath)
    return values


def _systemd_base(config: LaunchConfig, *, unit: str, memory_mib: int, runtime_seconds: int) -> list[str]:
    return [
        "sudo", "-n", "systemd-run", f"--unit={unit}", "--wait", "--pipe", "--collect",
        f"--uid={config.uid}", f"--gid={config.gid}", "--property=SupplementaryGroups=docker",
        "--property=CPUQuota=100%", f"--property=MemoryMax={memory_mib}M",
        "--property=MemorySwapMax=0", "--property=TasksMax=64",
        f"--property=RuntimeMaxSec={runtime_seconds}",
    ]


def build_sdk_argv(config: LaunchConfig, *, python: str = "/usr/bin/python3") -> list[str]:
    env = bounded_environment(config)
    env.update({"PINT_SDK_DEADLINE_EPOCH": str(config.sdk_deadline)})
    return _systemd_base(config, unit=config.sdk_unit, memory_mib=768, runtime_seconds=SDK_SECONDS) + \
        _setenv(env) + ["--working-directory=" + str(config.workspace), "--", python,
                        "tools/pint_ci_sdk_setup.py", "--site-dir", str(config.sdk_site),
                        "--wheel-dir", str(config.wheel_dir), "--public-contract",
                        str(config.workspace / "PINT_PUBLIC_RUNTIME_RESOURCE_CONTRACT.json")]


def build_parent_argv(config: LaunchConfig, *, python: str = "/usr/bin/python3") -> list[str]:
    env = bounded_environment(config, pythonpath=config.sdk_site)
    env.update({"PINT_SDK_SITE": str(config.sdk_site)})
    return _systemd_base(config, unit=config.parent_unit, memory_mib=512, runtime_seconds=PARENT_SECONDS) + \
        _setenv(env) + ["--working-directory=" + str(config.workspace), "--", python, DRIVER_RELATIVE]


def _bounded_bytes(value: str | bytes, *, limit: int = MAX_EVIDENCE_BYTES) -> tuple[bytes, bool]:
    raw = value if isinstance(value, bytes) else value.encode("utf-8", "replace")
    return raw[:limit], len(raw) > limit


def _write_evidence(path: Path, value: str | bytes) -> dict[str, Any]:
    bounded, truncated = _bounded_bytes(value)
    path.write_bytes(bounded)
    path.chmod(0o600)
    return {"path": str(path), "bytes": len(bounded), "truncated": truncated,
            "sha256": hashlib.sha256(bounded).hexdigest()}


def _result_rc(result: Any) -> int:
    return int(getattr(result, "returncode", 2))


def _run(runner: Callable[..., Any], argv: list[str], config: LaunchConfig) -> Any:
    return runner(argv, cwd=str(config.workspace), env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                   capture_output=True, text=True, timeout=max(JOB_SECONDS, SDK_SECONDS) + 120)


def _write_summary(config: LaunchConfig, summary: dict[str, Any]) -> None:
    path = config.evidence_dir / "operation-summary.json"
    path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def run_operation(config: LaunchConfig, *, runner: Callable[..., Any] = subprocess.run) -> int:
    """Run controlled SDK then parent launch, retaining bounded evidence."""
    # This is the operation's first action.  It must precede owned temporary
    # directories, prerequisite probes, systemd units, network, or SDK setup.
    try:
        verify_public_contract(config.workspace / "PINT_PUBLIC_RUNTIME_RESOURCE_CONTRACT.json")
    except (OSError, PublicContractError):
        return 2
    config.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.sdk_site.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.wheel_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.docker_config.mkdir(mode=0o700, parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "schema": "glee.pint.original_ci_operation.v1",
        "status": "STARTING",
        "attempt": config.attempt,
        "sdk_unit": config.sdk_unit,
        "parent_unit": config.parent_unit,
        "sdk_memory_mib": 768,
        "parent_memory_mib": 512,
        "sdk_seconds": SDK_SECONDS,
        "parent_seconds": PARENT_SECONDS,
        "job_seconds": JOB_SECONDS,
        "driver": DRIVER_RELATIVE,
        "effects": {"sdk_install": "NOT_STARTED", "driver": "NOT_STARTED"},
    }
    try:
        for prereq in (["sudo", "-n", "-v"], ["sudo", "-n", "systemd-run", "--version"], ["/usr/bin/python3", "--version"]):
            check = _run(runner, prereq, config)
            if _result_rc(check) != 0:
                raise OperationError("launcher_prerequisite_failed")
        sdk = _run(runner, build_sdk_argv(config), config)
        summary["effects"]["sdk_install"] = "SUCCEEDED" if _result_rc(sdk) == 0 else "FAILED"
        summary["sdk_returncode"] = _result_rc(sdk)
        summary["sdk_stdout"] = _write_evidence(config.evidence_dir / "sdk.stdout", getattr(sdk, "stdout", ""))
        summary["sdk_stderr"] = _write_evidence(config.evidence_dir / "sdk.stderr", getattr(sdk, "stderr", ""))
        if _result_rc(sdk) != 0:
            summary["status"] = "SDK_SETUP_FAILED"
            _write_summary(config, summary)
            return _result_rc(sdk) or 2
        driver = _run(runner, build_parent_argv(config), config)
        summary["effects"]["driver"] = "SUCCEEDED" if _result_rc(driver) == 0 else "FAILED"
        summary["driver_returncode"] = _result_rc(driver)
        summary["driver_stdout"] = _write_evidence(config.evidence_dir / "driver.stdout", getattr(driver, "stdout", ""))
        summary["driver_stderr"] = _write_evidence(config.evidence_dir / "driver.stderr", getattr(driver, "stderr", ""))
        summary["status"] = "DRIVER_COMPLETE" if _result_rc(driver) == 0 else "DRIVER_FAILED"
        _write_summary(config, summary)
        return _result_rc(driver)
    except (OSError, OperationError, subprocess.SubprocessError) as exc:
        summary["status"] = "LAUNCHER_FAILED"
        summary["failure_reason"] = str(exc) if isinstance(exc, OperationError) else type(exc).__name__
        _write_summary(config, summary)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="manual-only complete Pint CI operation")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args()
    try:
        config = make_config(workspace=args.workspace, runner_temp=args.runner_temp,
                             run_id=args.run_id, attempt=args.attempt, uid=os.getuid(), gid=os.getgid())
    except OperationError as exc:
        print(f"PINT_CI_REFUSED:{exc}")
        return 2
    rc = run_operation(config)
    print(f"PINT_CI_OPERATION:{config.evidence_dir}:returncode={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
