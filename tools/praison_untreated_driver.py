#!/usr/bin/env python3
"""Portable original PraisonAI untreated-control runner.

Public-safe: private SWE-bench row values are fetched on the runner from the
pinned Parquet shard and never printed/uploaded. Only sanitized counts, hashes,
and an opaque encrypted bounded evidence envelope are emitted.
"""
from __future__ import annotations

import base64
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import pyarrow.parquet as pq

REV = "babb27e45e072219195db7a744bbf0d3c1a36e56"
BASE = "016f020718dca4e75d876116858febe3d0a2f2a5"
IMAGE_REPO = "starryzhang/sweb.eval.x86_64.mervinpraison_1776_praisonai-801"
IMAGE_MANIFEST = "sha256:ddd6fd747c309801272c53629aa5b50bb58d14ec0f2417f0dc166a4d691b5b34"
IMAGE_CONFIG = "sha256:b777669960f75f86b0622d21b6efc14fe937945f7c652191ff892e7142a0703e"
IMAGE_DIFF_IDS = ['sha256:185e04da9d947141fd703dbf36361bdc2ff77cc27cbf500fb9f4881cb5ddbe95', 'sha256:607ddfe5f3c3f9e9df2b45f6275ad18bc76e49fdebcf0777c1c02c66f5012956', 'sha256:0dd5860cbc60e77cc364ce36be1a9055d4139f2123324e14f756af1af719ffb0', 'sha256:08e14ec5b7497da231d70d47d1d80440ba7d9997d43c0796a8394923bbc98183', 'sha256:a957db1d68d629b71168e4592e1b3882b5718c00ed87b5df6123c9030bcd1ad2', 'sha256:c1eb2b22a626daba2e21f42efbf50ac14e27c7aa8cdc0bbfc62975698cc1080a', 'sha256:e6ba6b8b18c11c430a1feb747e05461506d384480779ee6565246cfff96cc56d', 'sha256:d270b8debb9ab51f470f685bf5da71a100a3f132c8f80f841e1ca38df0824f92']
PARQUET_URL = f"https://huggingface.co/datasets/SWE-bench-Live/SWE-bench-Live/resolve/{REV}/data/full-00001-of-00002.parquet"
PARQUET_SIZE = 49_856_992
PARQUET_SHA = "b8cd02f881baf1621b6ed17a2980f82a002d7e895c45c8653b0b696467dbf72e"
PARQUET_ETAG = '"0c829aa2ca28e41e234497056a74b51c78336f12ec9e4f5adaff4d296046693b"'
PARQUET_ABSOLUTE_ROW = 1804
PARQUET_FIRST_SHARD_ROWS = 944
PARQUET_LOCAL_ROW = PARQUET_ABSOLUTE_ROW - PARQUET_FIRST_SHARD_ROWS
PUBLIC_SHA = "5538d72e594494839a8bce3e8a59eb476de65a05fe5db2bbb6b497fabf51c8f8"
EVALUATOR_SHA = "616c68561863b65ce4ad38b8e3e1d0f79d87774a03054970cb5040272268efe2"
# SHA-256 of the exact pinned published_driver_235.py parse_pytest function
# source used by the offline source-comparison proof.
OFFICIAL_PARSER_SOURCE_SHA256 = "bef58a9cba1def82b018aefcc341d18868a74d2bdfe60db2a7242525a11a7d95"
OP_DEADLINE, CLEANUP_MARGIN, RAW_CAP, EXPORT_CAP = 3600, 120, 32 * 1024 * 1024, 1 * 1024 * 1024
PYARROW_VERSION = "26.0.1"
PYARROW_WHEEL_SHA = "c718bf97a92a6dea97fd1062c3b9f9e2e83cb9cc926e752289fa4ffff41738f9"
PYARROW_WHEEL_URL = "https://files.pythonhosted.org/packages/d3/79/e2fc9b1317b7a21e7bcd57eb035cac3fe72f47af3efe2ec3b4dea9a08a04/pyarrow-26.0.1-cp312-cp312-manylinux_2_28_x86_64.whl"
RECIPIENT_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxOyfNi4T69kCGQEbKUoG
wTr6z9jfCDJ9frfUw+w6AtkWR+dGGg/9P963yKb3wMRKjGELGnCl3TVS6w357Va5
5FGtFR2pC9z0qnKGHyMndjkJVIcf7gfm0M6NU9lzduRcZXevsCnXzNVBmyJw50lB
QjC8gvKEI0HGjIB4lnFT3635YDy9MtZ8nea0bkEhp37Ozd9u4KW8zpAANerac2J2
ImGInl8dZg2xCB/1D8iLJIrhFarmaUBchvVxc4reME3N8HeUHHwb6UYxUnDHjxox
wVtlLjlWfUNDfdMh1fE5/TcnozQSar3VYnpZ/P+Q+E/FQo3824eWw/N0UoOzAQxj
TP1I09RH21oxC3Tj+3NOPf2CTLk+oDUKEx+WV6XlaX1DsWrO/WlttCktNlRnWG6l
7KdzgABaSYnknnPZZ7u+LFQaravJOG6eQJpWeU+N3JKXGi2RK5qb7L5GsCCGk2cw
yYAFapkoLtw9FjT759fzIpa0wPaR5U0ExsHhnwljMO3TAgMBAAE=
-----END PUBLIC KEY-----
"""

SAFE_FAILURE_REASONS = {
    "image_inspect_failed", "pinned_image_pull_failed", "pinned_image_not_verified",
    "parquet_revision_or_etag_mismatch", "parquet_transfer_cap_exceeded", "parquet_integrity_mismatch",
    "parquet_rowgroup_identity_mismatch", "parquet_target_row_missing", "public_row_binding_mismatch",
    "original_parser_command_binding_mismatch", "base_commit_identity_mismatch", "container_create_failed",
    "container_start_failed", "created_pid_not_zero", "pid_birth_missing", "cleanup_or_capture_unproven",
    "operation_root_reuse_denied", "image_identity_or_diffid_mismatch",
    "benchmark_parser_coverage_mismatch", "benchmark_accounting_invalid", "raw_log_capture_cap_exceeded",
    "source_archive_commit_mismatch", "source_archive_missing",
    "bootstrap_ownership_invalid", "container_exit_unobserved", "container_uid_unobserved",
}

VALID_PARSED_STATUSES = frozenset({"pass", "fail", "skip", "error", "xfail"})


def digest(v) -> str:
    # Match the canonical public-row binder's ASCII-escaped JSON contract.
    return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def run(argv, *, timeout=30, env=None, check=False, text=True, stdin=None, input_data=None, cwd=None):
    safe = env or {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.environ.get("RUNNER_TEMP", "/tmp"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(argv, timeout=timeout, env=safe, stdin=stdin, input=input_data, cwd=cwd, capture_output=True, text=text, check=check)


def verify_parent_budget(*, cgroup_root: Path = Path("/sys/fs/cgroup"), proc_cgroup: Path = Path("/proc/self/cgroup"), expected_unit: str | None = None) -> dict:
    """Verify the actual current process cgroup, never caller JSON or host rootfs."""
    try:
        line = next(item for item in proc_cgroup.read_text().splitlines() if item.startswith("0::"))
        relative = line.split(":", 2)[2].strip().lstrip("/")
        scope = cgroup_root / relative
        controllers = (scope / "cgroup.controllers").read_text().split()
        cpu_parts = (scope / "cpu.max").read_text().split()
        memory_raw = (scope / "memory.max").read_text().strip()
        swap_raw = (scope / "memory.swap.max").read_text().strip()
        pids_raw = (scope / "pids.max").read_text().strip()
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "current_process_cgroup_unreadable", "error_type": type(exc).__name__}
    if expected_unit and expected_unit not in ("/" + relative):
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "current_process_not_in_owned_parent_unit", "cgroup": "/" + relative}
    if not all(x in controllers for x in ("cpu", "memory", "pids")):
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "cgroup_v2_cpu_memory_pids_unavailable", "cgroup": "/" + relative}
    if len(cpu_parts) != 2 or cpu_parts[0] == "max":
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_cpu_bound_unlimited", "cgroup": "/" + relative}
    if memory_raw == "max":
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_memory_bound_unlimited", "cgroup": "/" + relative}
    if swap_raw != "0":
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_swap_bound_not_zero", "swap_max": swap_raw, "cgroup": "/" + relative}
    quota, period, memory_max = int(cpu_parts[0]), int(cpu_parts[1]), int(memory_raw)
    if quota != period:
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_cpu_bound_not_exactly_one_cpu", "cpu_quota": quota, "cpu_period": period, "cgroup": "/" + relative}
    if memory_max != 512 * 1024**2:
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_memory_bound_not_exactly_512_mib", "memory_max": memory_max, "cgroup": "/" + relative}
    if pids_raw != "64":
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "parent_tasks_bound_not_exactly_64", "pids_max": pids_raw, "cgroup": "/" + relative}
    return {"status": "PARENT_BUDGET_VERIFIED", "cgroup": "/" + relative, "memory_max": memory_max, "swap_max": swap_raw, "pids_max": int(pids_raw), "cpu_quota": quota, "cpu_period": period}


def read_private_row(path: Path) -> dict:
    pf = pq.ParquetFile(path)
    if pf.metadata.num_rows != PARQUET_FIRST_SHARD_ROWS or pf.num_row_groups != 1 or not 0 <= PARQUET_LOCAL_ROW < pf.metadata.num_rows:
        raise RuntimeError("parquet_rowgroup_identity_mismatch")
    fields = ("repo", "instance_id", "base_commit", "created_at", "docker_image", "problem_statement", "patch", "test_patch", "test_cmds", "FAIL_TO_PASS", "PASS_TO_PASS", "rebuild_cmds", "log_parser")
    values = {}
    for field in fields:
        for i, batch in enumerate(pf.iter_batches(batch_size=1, row_groups=[0], columns=[field], use_threads=False)):
            if i == PARQUET_LOCAL_ROW:
                values[field] = batch.column(0).to_pylist()[0]
                break
        else:
            raise RuntimeError("parquet_target_row_missing")
    if isinstance(values["created_at"], datetime):
        values["created_at"] = values["created_at"].replace(tzinfo=None).isoformat(timespec="seconds")
    public = {k: values[k] for k in ("repo", "instance_id", "base_commit", "created_at", "docker_image", "problem_statement")}
    if digest(public) != PUBLIC_SHA or public["base_commit"] != BASE or public["docker_image"] != IMAGE_REPO:
        raise RuntimeError("public_row_binding_mismatch")
    if values["log_parser"] != "pytest" or not isinstance(values["test_cmds"], list) or not values["test_cmds"] or not all(isinstance(command, str) and command for command in values["test_cmds"]) or not isinstance(values["rebuild_cmds"], list) or len(values["rebuild_cmds"]) != 0:
        raise RuntimeError("original_parser_command_binding_mismatch")
    return values


def original_test_script(test_cmds: list[str]) -> str:
    """Preserve the evaluator's original command order and shell wrapper."""
    if not test_cmds or not all(isinstance(command, str) and command for command in test_cmds):
        raise RuntimeError("original_test_commands_invalid")
    return " ; ".join(test_cmds) + "\n"


def validate_source_commit(observed_commit: str, expected_commit: str) -> None:
    if observed_commit != expected_commit:
        raise RuntimeError("base_commit_identity_mismatch")


def validate_source_archive_commit(archive_commit: str, expected_commit: str) -> None:
    if archive_commit != expected_commit:
        raise RuntimeError("source_archive_commit_mismatch")


def source_fetch_witness(repo: Path, archive: Path, expected_commit: str) -> dict:
    """Bind FETCH_HEAD and git-archive metadata before container effects."""
    observed_commit = run(["git", "-C", str(repo), "rev-parse", "FETCH_HEAD"], timeout=30).stdout.strip()
    validate_source_commit(observed_commit, expected_commit)
    if not archive.is_file() or archive.stat().st_size <= 0:
        raise RuntimeError("source_archive_missing")
    with archive.open("rb") as archive_stream:
        result = run(["git", "get-tar-commit-id"], timeout=30, stdin=archive_stream, cwd="/")
    if result.returncode != 0:
        raise RuntimeError("source_archive_commit_mismatch")
    archive_commit = result.stdout.strip()
    validate_source_archive_commit(archive_commit, expected_commit)
    return {"status": "SOURCE_FETCH_VERIFIED", "commit_match": True, "archive_commit_match": True, "archive_bytes": archive.stat().st_size, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}


def verify_image(docker: str, cfg: str) -> dict:
    inspect_ref = IMAGE_REPO + "@" + IMAGE_MANIFEST
    result = run([docker, "--config", cfg, "--host", "unix:///var/run/docker.sock", "image", "inspect", inspect_ref], timeout=30)
    if result.returncode != 0:
        return {"status": "IMAGE_ABSENT", "failure_reason": "image_inspect_failed", "observations": {"inspect_reference": inspect_ref, "inspect_returncode": result.returncode, "repo_digest_match": False, "identity_mode": "UNOBSERVED", "diff_ids_match": False, "diff_id_count": 0}}
    row = json.loads(result.stdout)[0]
    repo_digests = row.get("RepoDigests") or []
    rootfs = (row.get("RootFS") or {}).get("Layers") or []
    image_id = row.get("Id")
    config_digest = image_id
    if image_id == IMAGE_CONFIG:
        identity_mode = "CONFIG_DIGEST"
    elif image_id == IMAGE_MANIFEST:
        identity_mode = "MANIFEST_DIGEST"
    else:
        identity_mode = "UNSUPPORTED_ID"
    repo_digest_match = any(IMAGE_MANIFEST in x for x in repo_digests)
    diff_ids_match = rootfs == IMAGE_DIFF_IDS
    failed_predicates = []
    if not repo_digest_match:
        failed_predicates.append("repo_digest_match")
    if identity_mode == "UNSUPPORTED_ID":
        failed_predicates.append("identity_mode")
    if not diff_ids_match:
        failed_predicates.append("diff_ids_match")
    return {
        "status": "IMAGE_VERIFIED" if not failed_predicates else "IMAGE_UNVERIFIED",
        "failure_reason": None if not failed_predicates else "image_predicate_failed:" + ",".join(failed_predicates),
        "repo_digest_match": repo_digest_match,
        "image_id": image_id,
        "configuration_digest": config_digest,
        "identity_mode": identity_mode,
        "diff_id_count": len(rootfs),
        "diff_ids_match": diff_ids_match,
        "observations": {"inspect_reference": inspect_ref, "repo_digests": repo_digests, "observed_image_id": image_id, "observed_diff_ids": rootfs, "expected_manifest": IMAGE_MANIFEST, "expected_config": IMAGE_CONFIG, "expected_diff_id_count": len(IMAGE_DIFF_IDS), "failed_predicates": failed_predicates},
    }


def verify_docker_storage(docker: str, cfg: str, *, minimum_free_bytes: int = 8 * 1024**3) -> dict:
    """Prove free space on the actual Docker data-root volume before pull."""
    info = run([docker, "--config", cfg, "--host", "unix:///var/run/docker.sock", "info", "--format", "{{json .}}"], timeout=30)
    if info.returncode != 0:
        return {"status": "UNSUPPORTED_STORAGE", "reason": "docker_info_failed"}
    try:
        data = json.loads(info.stdout); root_dir = Path(data["DockerRootDir"]); free = shutil.disk_usage(root_dir).free
    except (KeyError, OSError, ValueError) as exc:
        return {"status": "UNSUPPORTED_STORAGE", "reason": "docker_root_volume_unreadable", "error_type": type(exc).__name__}
    result = {"status": "DOCKER_ROOT_STORAGE_VERIFIED" if free >= minimum_free_bytes else "INSUFFICIENT_DOCKER_ROOT_STORAGE", "docker_root_dir": str(root_dir), "free_bytes": free, "required_free_bytes": minimum_free_bytes, "requirement": "image_pull_plus_Parquet_SDK_shard_plus_reader_logs_archive_plus_2GiB_floor"}
    return result


def validate_container_inspect(row: dict, *, cid: str, name: str, nonce: str, uid: int, gid: int, image_ids: set[str]) -> None:
    config, host, labels = row.get("Config") or {}, row.get("HostConfig") or {}, (row.get("Config") or {}).get("Labels") or {}
    if row.get("Id") != cid or row.get("Image") not in image_ids:
        raise RuntimeError("container_identity_mismatch")
    if labels.get("glee.owner") != "sanji" or labels.get("glee.qualifier") != "praisonai" or labels.get("glee.nonce") != nonce or labels.get("glee.name") != name:
        raise RuntimeError("container_owner_nonce_label_mismatch")
    if config.get("User") != f"{uid}:{gid}" or config.get("WorkingDir") != "/testbed":
        raise RuntimeError("container_uid_or_workdir_mismatch")
    if (host.get("Memory") != 2 * 1024**3 or host.get("MemorySwap") != 2 * 1024**3 or host.get("NanoCpus") != 1_000_000_000 or host.get("NetworkMode") != "none" or host.get("ReadonlyRootfs") is not True or host.get("PidsLimit") != 64 or host.get("Privileged") is True or "ALL" not in (host.get("CapDrop") or []) or host.get("CapAdd") or not any(str(x).split(":", 1)[0] == "no-new-privileges" for x in (host.get("SecurityOpt") or []))):
        raise RuntimeError("container_resource_policy_mismatch")
    env = config.get("Env") or []
    if any(any(secret in str(item).split("=", 1)[0].upper() for secret in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "OPENAI", "CODEX_HOME")) for item in env):
        raise RuntimeError("container_credentials_exposed")
    tmpfs = host.get("Tmpfs") or {}
    for destination, size in (("/tmp", "256m"), ("/testbed", "1024m"), ("/.mem0", "16m")):
        values = tmpfs.get(destination); values = values if isinstance(values, list) else [values]
        if not any(isinstance(item, str) and all(flag in item for flag in ("rw", "noexec", "nosuid", "nodev", f"size={size}", f"uid={uid}", f"gid={gid}")) for item in values):
            raise RuntimeError("container_tmpfs_policy_mismatch")
    if "mode=0700" not in str(tmpfs.get("/.mem0", "")):
        raise RuntimeError("container_tmpfs_policy_mismatch")
    if not any(m.get("Destination") == "/input" and m.get("Type") == "bind" and m.get("RW") is False for m in (row.get("Mounts") or [])):
        raise RuntimeError("container_input_mount_mismatch")


def parse_official_pytest(log: str) -> dict[str, str]:
    """Pinned SWE-bench official pytest parser semantics."""
    out: dict[str, str] = {}
    for line in log.splitlines():
        status = next((item for item in ("FAILED", "PASSED", "SKIPPED", "ERROR", "XFAIL") if line.startswith(item)), None)
        if status is None:
            continue
        # The pinned published parser normalizes the separator for every
        # recognized status, not only FAILED.
        line = line.replace(" - ", " ")
        parts = line.split()
        if len(parts) <= 1:
            continue
        out[parts[1]] = "pass" if status in {"PASSED", "XFAIL"} else ("skip" if status == "SKIPPED" else "fail")
    return out


def parse_pytest(log: str) -> dict[str, str]:
    """Compatibility name for the pinned official parser above."""
    return parse_official_pytest(log)


def observe_owned_path(path: Path, *, uid: int, gid: int) -> tuple[bool, bool]:
    """Return ownership and a real read-back result for a host path."""
    try:
        stat = path.stat()
        if path.is_dir():
            next(iter(path.iterdir()), None)
        else:
            path.read_bytes()
        return stat.st_uid == uid and stat.st_gid == gid, True
    except (OSError, StopIteration):
        return False, False


def validate_bootstrap(*, process_uid: int | None, process_gid: int | None,
                       workspace_uid: int | None, workspace_gid: int | None,
                       tmpfs_uid: int | None, tmpfs_gid: int | None,
                       workspace_readback: bool | None,
                       tmpfs_readback: bool | None) -> dict:
    """Require matching non-root UID/GID and read-back ownership witnesses."""
    if process_uid is None or process_gid is None:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "UID_UNOBSERVED"}
    if process_uid == 0 or process_gid == 0:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "UNPRIVILEGED_UID_REQUIRED"}
    if workspace_uid != process_uid or workspace_gid != process_gid:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "GIT_DUBIOUS_OWNERSHIP"}
    if tmpfs_uid != process_uid or tmpfs_gid != process_gid:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "TMPFS_OWNER_MISMATCH"}
    if workspace_readback is not True or tmpfs_readback is not True:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "BOOTSTRAP_OWNERSHIP_READBACK_UNPROVEN"}
    return {"status": "BOOTSTRAP_VERIFIED", "safe_directory_bypass": False}


def parse_bootstrap_witness(log: str, *, expected_uid: int, expected_gid: int) -> dict:
    """Parse the container's explicit id/stat read-back witness."""
    prefix = "GLEE_BOOTSTRAP "
    line = next((item for item in log.splitlines() if item.startswith(prefix)), None)
    if line is None:
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "BOOTSTRAP_OWNERSHIP_READBACK_UNPROVEN"}
    values = {}
    for item in line[len(prefix):].split():
        if "=" in item:
            key, value = item.split("=", 1)
            values[key] = value
    try:
        workspace_uid, workspace_gid = (int(item) for item in values["testbed"].split(":", 1))
        tmpfs_uid, tmpfs_gid = (int(item) for item in values["tmpfs"].split(":", 1))
        process_uid, process_gid = int(values["uid"]), int(values["gid"])
        cache_uid, cache_gid, cache_mode = values["mem0"].split(":")
        if values.get("mem0_write") != "1":
            raise ValueError("bounded_cache_write_unproven")
        if (int(cache_uid), int(cache_gid), cache_mode) != (expected_uid, expected_gid, "700"):
            raise ValueError("bounded_cache_ownership_or_mode")
    except (KeyError, ValueError):
        return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": "BOOTSTRAP_OWNERSHIP_READBACK_UNPROVEN"}
    return validate_bootstrap(process_uid=process_uid, process_gid=process_gid,
                              workspace_uid=workspace_uid, workspace_gid=workspace_gid,
                              tmpfs_uid=tmpfs_uid, tmpfs_gid=tmpfs_gid,
                              workspace_readback=process_uid == expected_uid and process_gid == expected_gid,
                              tmpfs_readback=process_uid == expected_uid and process_gid == expected_gid)


def _sanitized_accounting_failure(code: str, **details) -> dict:
    """Build a public-safe accounting result without private identity names."""
    return {"status": "INVALID_BENCHMARK_EVIDENCE", "failure_code": code, **details}


def lifecycle_witness_valid(container_exit: dict | None) -> bool:
    """Require running birth and exited finish witnesses before cleanup."""
    if not container_exit or container_exit.get("pid_birth_state") != "running":
        return False
    if not isinstance(container_exit.get("pid"), int) or container_exit["pid"] <= 0:
        return False
    started_at = container_exit.get("started_at")
    if not isinstance(started_at, str) or not started_at or started_at.startswith("0001-01-01"):
        return False
    if container_exit.get("status") not in {"exited", "dead"}:
        return False
    if not isinstance(container_exit.get("returncode"), int):
        return False
    finished_at = container_exit.get("exited_at")
    return isinstance(finished_at, str) and bool(finished_at) and not finished_at.startswith("0001-01-01")


def validate_accounting(*, expected_ids, observed: dict[str, str], stage: str,
                        effect_flags: dict[str, str], container_exit: dict | None,
                        uid: int | None, gid: int | None, bootstrap: dict | None,
                        input_owned: bool | None, temp_owned: bool | None,
                        input_readback: bool | None, temp_readback: bool | None,
                        encrypted_evidence: dict | None = None) -> dict:
    """Require private identity membership and complete lifecycle evidence.

    Only counts are returned. The expected and observed identities never enter
    the sanitized report or envelope metadata. Extra official parser identities
    are valid when all required identities are present.
    """
    expected = list(expected_ids)
    if not expected:
        return _sanitized_accounting_failure("EXPECTED_IDENTITY_SET_EMPTY", observed_count=len(observed))
    duplicate_count = len(expected) - len(set(expected))
    if duplicate_count:
        return _sanitized_accounting_failure("EXPECTED_IDENTITY_SET_INVALID", duplicate_expected_count=duplicate_count)
    invalid_values = sum(value not in VALID_PARSED_STATUSES for value in observed.values())
    if invalid_values:
        return _sanitized_accounting_failure("STATUS_VALUE_INVALID", invalid_status_count=invalid_values)
    missing_count = len(set(expected) - set(observed))
    unexpected_count = len(set(observed) - set(expected))
    if missing_count:
        return _sanitized_accounting_failure("STATUS_IDENTITY_ACCOUNTING_MISMATCH", missing_count=missing_count, unexpected_count=unexpected_count, observed_count=len(observed), required_count=len(expected))
    if stage in {"", "starting", "unknown", "image_admission"}:
        return _sanitized_accounting_failure("STAGE_INCOMPLETE", stage=stage)
    required_flags = ("container_create", "container_start", "benchmark_test", "cleanup")
    missing_flags = sum(effect_flags.get(key) not in {"SUCCEEDED", "FAILED"} for key in required_flags)
    if missing_flags:
        return _sanitized_accounting_failure("EFFECT_STAGE_INCOMPLETE", missing_stage_count=missing_flags)
    if not lifecycle_witness_valid(container_exit):
        return _sanitized_accounting_failure("CONTAINER_EXIT_UNOBSERVED")
    if uid is None or gid is None:
        return _sanitized_accounting_failure("UID_UNOBSERVED")
    if uid == 0 or gid == 0:
        return _sanitized_accounting_failure("UNPRIVILEGED_UID_REQUIRED")
    if not bootstrap or bootstrap.get("status") != "BOOTSTRAP_VERIFIED":
        return _sanitized_accounting_failure("BOOTSTRAP_OWNERSHIP_UNPROVEN")
    if input_owned is not True or temp_owned is not True or input_readback is not True or temp_readback is not True:
        return _sanitized_accounting_failure("PRIVATE_PATH_OWNERSHIP_OR_READBACK_UNPROVEN")
    if encrypted_evidence is not None:
        if encrypted_evidence.get("retained") is not True:
            return _sanitized_accounting_failure("ENCRYPTED_EVIDENCE_NOT_RETAINED")
        if encrypted_evidence.get("export_bytes", 0) > encrypted_evidence.get("export_cap_bytes", 0):
            return _sanitized_accounting_failure("ENCRYPTED_EVIDENCE_EXPORT_EXCEEDS_CAP")
    return {"status": "VALID_BENCHMARK_EVIDENCE", "required_count": len(expected), "observed_count": len(observed), "unexpected_count": unexpected_count}


class Lease:
    def __init__(self, root: Path, token: str):
        self.root, self.token, self.state = root, token, "NEW"
        self.identity = {}
    def begin(self):
        if self.root.exists():
            raise RuntimeError("operation_root_reuse_denied")
        self.root.mkdir(mode=0o700, parents=True); self.state = "RUNNING"
        (self.root / "operation.json").write_text(json.dumps({"state": self.state, "token_sha256": hashlib.sha256(self.token.encode()).hexdigest()}) + "\n")
    def finish(self, state):
        self.state = state
        (self.root / "result.json").write_text(json.dumps({"state": state, "identity": self.identity}) + "\n")


class OfflineTransport:
    """Stateful fixture transport used only by the private pre-dispatch proof."""
    def __init__(self, *, timeout=False, wrong_image=False):
        self.state, self.timeout, self.wrong_image = "NEW", timeout, wrong_image
        self.cid, self.pid_birth = "offline-cid", None
    def create(self, image=IMAGE_MANIFEST):
        if self.state != "NEW": raise RuntimeError("create_replay")
        self.state = "CREATED"; return self.cid
    def inspect(self):
        image = "wrong-image" if self.wrong_image else IMAGE_MANIFEST
        return {"image": image, "pid": 0 if self.state == "CREATED" else (4242 if self.state == "RUNNING" else 0), "started_at": "2026-11-10T00:00:00Z", "state": self.state}
    def start(self):
        if self.state != "CREATED": raise RuntimeError("start_state")
        self.state = "RUNNING"; self.pid_birth = self.inspect(); return self.pid_birth
    def logs(self, raw):
        if self.timeout: raise TimeoutError("fixture_timeout")
        if self.state != "RUNNING": raise RuntimeError("logs_state")
        self.state = "EXITED"; return raw
    def remove(self):
        if self.state not in {"EXITED", "RUNNING", "CREATED"}: raise RuntimeError("remove_state")
        self.state = "REMOVED"
    def absent(self): return self.state == "REMOVED"


def offline_control(private_row: dict, transport: OfflineTransport, root: Path) -> dict:
    lease = Lease(root, "offline-token-123456"); lease.begin()
    cid = transport.create(); created = transport.inspect()
    if created["pid"] != 0 or created["image"] != IMAGE_MANIFEST: raise RuntimeError("created_identity_check")
    lease.identity = {"cid": cid, "created_pid": created["pid"]}
    running = transport.start()
    if running["pid"] <= 0 or not running["started_at"]: raise RuntimeError("pid_birth_check")
    lease.identity["pid_birth"] = running
    raw = ("FAILED " + "\nFAILED ".join(private_row["FAIL_TO_PASS"]) + "\n" + "\n".join("PASSED " + x for x in private_row["PASS_TO_PASS"]) + "\n").encode()
    capture = transport.logs(raw)
    parsed = parse_pytest(capture.decode())
    expected = private_row["FAIL_TO_PASS"] + private_row["PASS_TO_PASS"]
    uid, gid = os.getuid(), os.getgid()
    bootstrap = validate_bootstrap(process_uid=uid, process_gid=gid, workspace_uid=uid, workspace_gid=gid, tmpfs_uid=uid, tmpfs_gid=gid, workspace_readback=True, tmpfs_readback=True)
    accounting = validate_accounting(expected_ids=expected, observed=parsed, stage="cleanup", effect_flags={"container_create": "SUCCEEDED", "container_start": "SUCCEEDED", "benchmark_test": "SUCCEEDED", "cleanup": "SUCCEEDED"}, container_exit={"status": "exited", "returncode": 1, "exited_at": "2026-11-10T00:00:01Z", "pid": running["pid"], "started_at": running["started_at"], "pid_birth_state": "running"}, uid=uid, gid=gid, bootstrap=bootstrap, input_owned=True, temp_owned=True, input_readback=True, temp_readback=True)
    if accounting["status"] != "VALID_BENCHMARK_EVIDENCE": raise RuntimeError("offline_parser_coverage")
    transport.remove()
    if not transport.absent(): raise RuntimeError("offline_cleanup_absence")
    lease.finish("UNTREATED_EXPECTED_FAILURE_CONTROL")
    return {"status": "PASS", "required_total": accounting["required_count"], "observed_count": accounting["observed_count"], "pid_birth_bound": True, "cleanup_absence_proven": True, "parser": private_row["log_parser"]}


def emit_envelope(raw_files: list[Path], summary: dict, work: Path) -> dict:
    merged = work / "raw_logs.tar.gz"
    with merged.open("wb") as out:
        with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=6) as gz:
            for path in raw_files:
                gz.write(path.name.encode() + b"\n"); gz.write(path.read_bytes())
    key = work / "key.bin"; key.write_bytes(secrets.token_bytes(32)); iv = work / "iv.bin"; iv.write_bytes(secrets.token_bytes(16))
    cipher = work / "evidence.enc"; wrapped = work / "key.wrap"
    run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", str(merged), "-out", str(cipher), "-pass", "file:" + str(key)], timeout=30, check=True)
    keyiv = work / "keyiv.bin"; keyiv.write_bytes(key.read_bytes() + iv.read_bytes())
    pub = work / "recipient_public.pem"; pub.write_text(RECIPIENT_PUBLIC_KEY)
    run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(pub), "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "digest:sha256", "-in", str(keyiv), "-out", str(wrapped)], timeout=30, check=True)
    capture = summary.get("capture") or {}
    payload = {"schema": "glee.remote.praisonai.opaque_evidence.v1", "public_recipient_fingerprint_sha256": "3f687c06feebddfd318e6afad1fc4377be022fe4ba9f9b7b16b0491ce3ff942d", "ciphertext_sha256": hashlib.sha256(cipher.read_bytes()).hexdigest(), "wrapped_key_sha256": hashlib.sha256(wrapped.read_bytes()).hexdigest(), "ciphertext_bytes": cipher.stat().st_size, "wrapped_key_bytes": wrapped.stat().st_size, "raw_logs_complete": capture.get("complete") is True and capture.get("stdout_eof") is True and capture.get("stderr_eof") is True, "stream_eof": {"stdout": capture.get("stdout_eof") is True, "stderr": capture.get("stderr_eof") is True}, "summary": summary}
    envelope = json.dumps(payload, sort_keys=True).encode() + b"\nCIPHERTEXT_B64=" + base64.b64encode(cipher.read_bytes()) + b"\nWRAPPED_KEY_B64=" + base64.b64encode(wrapped.read_bytes())
    envelope_b64 = base64.b64encode(envelope)
    # Bound the complete printed export line, including the outer base64 and
    # its protocol prefix.  Checking only the binary envelope undercounts by
    # roughly 4/3 and can exceed the public wire cap.
    wire = b"GLEE_OPAQUE_EVIDENCE_B64=" + envelope_b64 + b"\n"
    if len(wire) > EXPORT_CAP:
        return {"status": "UNVERIFIED_EXPORT", "reason": "encrypted_evidence_exceeds_bounded_log_export", "export_bytes": len(wire), "payload": payload}
    return {"status": "OPAQUE_EVIDENCE_READY", "export_bytes": len(wire), "payload": payload, "envelope_b64": envelope_b64.decode()}


def retain_unknown_hold(root: Path, *, cid: str, nonce: str) -> Path:
    base = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    hold = base / ("glee-praisonai-unknown-held-" + secrets.token_hex(8))
    root.rename(hold); hold.chmod(0o700)
    custody = {"schema": "glee.remote.praisonai.unknown_hold.v1", "status": "UNKNOWN_HELD", "cid": cid, "nonce": nonce, "operation_root": str(hold), "recovery": "exact CID+nonce required; no replay by name"}
    (hold / "UNKNOWN_HELD.json").write_text(json.dumps(custody, sort_keys=True) + "\n"); (hold / "UNKNOWN_HELD.json").chmod(0o600)
    return hold


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="glee-praisonai-untreated-")); root.chmod(0o700)
    lease = Lease(root / "operation", secrets.token_hex(16))
    report = {"schema": "glee.remote.praisonai.original_untreated.v1", "status": "STARTING", "stage": "parent_preflight", "failure_reason": None, "effect_flags": {"dataset_fetch": "NOT_STARTED", "image_pull": "NOT_STARTED", "source_fetch": "NOT_STARTED", "container_create": "NOT_STARTED", "container_start": "NOT_STARTED", "benchmark_test": "NOT_STARTED", "cleanup": "NOT_STARTED"}, "instance_id": "MervinPraison__PraisonAI-801", "control_counts": {"FAIL_TO_PASS": "UNOBSERVED", "PASS_TO_PASS": "UNOBSERVED", "required_total": "UNOBSERVED"}, "provider_calls": 0, "model_subjects": 0}
    actual = None; docker = None; cfg = None; env = {}
    try:
        host_uid, host_gid = os.getuid(), os.getgid()
        if host_uid == 0 or host_gid == 0:
            report["status"] = "UNSUPPORTED_RUNNER"; report["failure_reason"] = "nonzero_uid_gid_required"; print(json.dumps(report, sort_keys=True)); return 2
        expected_parent_unit = os.environ.get("GLEE_PARENT_UNIT")
        if not expected_parent_unit:
            report["status"] = "UNSUPPORTED_PARENT_CONTROL"; report["parent_budget"] = {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "missing_workflow_owned_parent_unit"}; print(json.dumps(report, sort_keys=True)); return 2
        parent = verify_parent_budget(expected_unit=expected_parent_unit); report["parent_budget"] = parent
        if parent["status"] != "PARENT_BUDGET_VERIFIED": report["status"] = parent["status"]; print(json.dumps(report, sort_keys=True)); return 2
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"} or shutil.which("docker") is None:
            report["status"] = "UNSUPPORTED_RUNNER"; print(json.dumps(report, sort_keys=True)); return 2
        work = root / "work"; work.mkdir(mode=0o700); report["stage"] = "storage_preflight"
        docker = shutil.which("docker"); cfg = work / "docker-config"; cfg.mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(work)}
        DOCKER_ROOT_FREE_THRESHOLD = 14_947_208_004
        storage = verify_docker_storage(docker, str(cfg), minimum_free_bytes=DOCKER_ROOT_FREE_THRESHOLD); report["docker_root_storage"] = storage
        if storage["status"] != "DOCKER_ROOT_STORAGE_VERIFIED": report["status"] = storage["status"]; print(json.dumps(report, sort_keys=True)); return 2
        parquet = work / "full-00001-of-00002.parquet"; report["stage"] = "dataset_fetch"; report["effect_flags"]["dataset_fetch"] = "IN_PROGRESS"
        with urllib.request.urlopen(urllib.request.Request(PARQUET_URL, headers={"User-Agent": "GLEE-remote-praisonai-original-control/1"}), timeout=120) as response, parquet.open("wb") as out:
            # Hugging Face's final CDN response may omit X-Repo-Commit after
            # following the redirect; the exact immutable URL revision remains
            # the source proof, while ETag still binds the payload identity.
            repo_commit = response.headers.get("X-Repo-Commit") or (REV if f"/{REV}/" in PARQUET_URL else None)
            if repo_commit != REV or response.headers.get("ETag") != PARQUET_ETAG: raise RuntimeError("parquet_revision_or_etag_mismatch")
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > 64 * 1024 * 1024: raise RuntimeError("parquet_transfer_cap_exceeded")
                out.write(chunk)
        if total != PARQUET_SIZE or hashlib.sha256(parquet.read_bytes()).hexdigest() != PARQUET_SHA: raise RuntimeError("parquet_integrity_mismatch")
        report["effect_flags"]["dataset_fetch"] = "SUCCEEDED"; private = read_private_row(parquet); report["parser"] = private["log_parser"]; report["control_counts"] = {"FAIL_TO_PASS": len(private["FAIL_TO_PASS"]), "PASS_TO_PASS": len(private["PASS_TO_PASS"]), "required_total": len(private["FAIL_TO_PASS"]) + len(private["PASS_TO_PASS"])}; report["stage"] = "image_admission"
        image = verify_image(docker, str(cfg))
        if image["status"] == "IMAGE_ABSENT":
            report["effect_flags"]["image_pull"] = "IN_PROGRESS"
            pull = subprocess.run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "pull", "--quiet", IMAGE_REPO + "@" + IMAGE_MANIFEST], env=env, capture_output=True, text=True, timeout=900, check=False)
            if pull.returncode != 0: raise RuntimeError("pinned_image_pull_failed")
            image = verify_image(docker, str(cfg))
            report["effect_flags"]["image_pull"] = "SUCCEEDED"
        report["image"] = image
        if image["status"] != "IMAGE_VERIFIED": raise RuntimeError(image.get("failure_reason") or "pinned_image_not_verified")
        report["stage"] = "source_fetch"; report["effect_flags"]["source_fetch"] = "IN_PROGRESS"; repo = work / "source"; repo.mkdir(mode=0o700)
        run(["git", "init", "-q", str(repo)], timeout=30, check=True); run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/MervinPraison/PraisonAI.git"], timeout=30, check=True); run(["git", "-C", str(repo), "fetch", "--depth=1", "origin", BASE], timeout=900, check=True)
        validate_source_commit(run(["git", "-C", str(repo), "rev-parse", "FETCH_HEAD"], timeout=30).stdout.strip(), BASE)
        archive = work / "base_commit.tar"; run(["git", "-C", str(repo), "archive", "--format=tar", BASE, "-o", str(archive)], timeout=300, check=True); report["source_identity"] = source_fetch_witness(repo, archive, BASE); report["effect_flags"]["source_fetch"] = "SUCCEEDED"
        input_dir = work / "input"; input_dir.mkdir(mode=0o700)
        shutil.copy2(archive, input_dir / "base_commit.tar"); (input_dir / "test.patch").write_text(private["test_patch"]); (input_dir / "solution.patch").write_text(""); (input_dir / "test_cmd.sh").write_text(original_test_script(private["test_cmds"]))
        for p in input_dir.iterdir(): p.chmod(0o600)
        input_owned, input_readback = observe_owned_path(input_dir, uid=host_uid, gid=host_gid)
        temp_owned, temp_readback = observe_owned_path(work, uid=host_uid, gid=host_gid)
        report["path_ownership"] = {"input": "MATCHED_READBACK" if input_owned and input_readback else "UNPROVEN", "temporary": "MATCHED_READBACK" if temp_owned and temp_readback else "UNPROVEN"}
        if not (input_owned and input_readback and temp_owned and temp_readback):
            raise RuntimeError("bootstrap_ownership_invalid")
        lease.begin(); report["stage"] = "container_create"; report["effect_flags"]["container_create"] = "IN_PROGRESS"; cid = "glee-praisonai-untreated-" + secrets.token_hex(8); nonce = secrets.token_hex(16); lease.identity = {"cid": None, "name": cid, "nonce": nonce}
        args = [docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "create", "--name", cid, "--label", "glee.owner=sanji", "--label", "glee.qualifier=praisonai", "--label", "glee.nonce=" + nonce, "--label", "glee.name=" + cid, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=2g", "--memory-swap=2g", "--cpus=1", "--user=%s:%s" % (host_uid, host_gid), "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777,uid=%s,gid=%s" % (host_uid, host_gid), "--tmpfs=/testbed:rw,noexec,nosuid,nodev,size=1024m,mode=1777,uid=%s,gid=%s" % (host_uid, host_gid), "--tmpfs=/.mem0:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=%s,gid=%s" % (host_uid, host_gid), "--mount", "type=bind,src=%s,dst=/input,readonly" % input_dir, "--workdir=/testbed", "--entrypoint=/bin/bash", IMAGE_REPO + "@" + IMAGE_MANIFEST, "-lc", "set -euo pipefail; uid=$(id -u); gid=$(id -g); test \"$uid\" = \"%s\"; test \"$gid\" = \"%s\"; testbed_owner=$(stat -c '%%u:%%g' /testbed); tmpfs_owner=$(stat -c '%%u:%%g' /tmp); mem0_owner=$(stat -c '%%u:%%g:%%a' /.mem0); test \"$mem0_owner\" = \"$uid:$gid:700\"; cache_probe=$(mktemp /.mem0/.glee-write.XXXXXX); rm -f \"$cache_probe\"; test \"$testbed_owner\" = \"$uid:$gid\"; test \"$tmpfs_owner\" = \"$uid:$gid\"; printf 'GLEE_BOOTSTRAP uid=%%s gid=%%s testbed=%%s tmpfs=%%s mem0=%%s mem0_write=1\\n' \"$uid\" \"$gid\" \"$testbed_owner\" \"$tmpfs_owner\" \"$mem0_owner\"; rm -rf /testbed/* /testbed/.[!.]* /testbed/..?* 2>/dev/null || true; tar -xf /input/base_commit.tar -C /testbed; unset $(compgen -v | grep '^GIT_' || true); git -C /testbed init -q; git -C /testbed add -A; git -c user.name='GLEE control' -c user.email='control@invalid' -c commit.gpgsign=false -C /testbed commit -qm base; git -C /testbed apply --reject --whitespace=nowarn /input/test.patch; bash /input/test_cmd.sh" % (host_uid, host_gid)]
        created = run(args, timeout=30, env=env); 
        if created.returncode != 0: raise RuntimeError("container_create_failed")
        actual = created.stdout.strip(); lease.identity["cid"] = actual; report["effect_flags"]["container_create"] = "SUCCEEDED"; report["stage"] = "container_start"
        inspect = json.loads(run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "inspect", actual], timeout=30, env=env, check=True).stdout)[0]; validate_container_inspect(inspect, cid=actual, name=cid, nonce=nonce, uid=host_uid, gid=host_gid, image_ids={IMAGE_CONFIG, IMAGE_MANIFEST}); lease.identity["created_pid"] = (inspect.get("State") or {}).get("Pid", 0)
        if lease.identity["created_pid"] != 0: raise RuntimeError("created_pid_not_zero")
        report["effect_flags"]["container_start"] = "IN_PROGRESS"; started = run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "start", actual], timeout=30, env=env)
        if started.returncode != 0: raise RuntimeError("container_start_failed")
        report["effect_flags"]["container_start"] = "SUCCEEDED"; report["stage"] = "benchmark_test"; report["effect_flags"]["benchmark_test"] = "IN_PROGRESS"
        running = json.loads(run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "inspect", actual], timeout=30, env=env, check=True).stdout)[0]; running_state = running.get("State") or {}; lease.identity["pid_birth"] = {"pid": running_state.get("Pid"), "started_at": running_state.get("StartedAt"), "state": running_state.get("Status")}
        if lease.identity["pid_birth"]["state"] != "running" or not isinstance(lease.identity["pid_birth"]["pid"], int) or lease.identity["pid_birth"]["pid"] <= 0 or not isinstance(lease.identity["pid_birth"]["started_at"], str) or not lease.identity["pid_birth"]["started_at"] or lease.identity["pid_birth"]["started_at"].startswith("0001-01-01"): raise RuntimeError("pid_birth_missing")
        raw_out, raw_err = work / "stdout.raw", work / "stderr.raw"; proc = subprocess.Popen([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "logs", "--follow", actual], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env); outb, errb = proc.communicate(timeout=OP_DEADLINE - CLEANUP_MARGIN); raw_out.write_bytes(outb); raw_err.write_bytes(errb); capture_complete = proc.returncode == 0
        if len(outb) + len(errb) > RAW_CAP: raise RuntimeError("raw_log_capture_cap_exceeded")
        combined_log = (outb + b"\n" + errb).decode("utf-8", "replace")
        parsed = parse_pytest(combined_log)
        finished = json.loads(run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "inspect", actual], timeout=30, env=env, check=True).stdout)[0]
        finished_state = finished.get("State") or {}
        container_exit = {"status": finished_state.get("Status"), "returncode": finished_state.get("ExitCode"), "exited_at": finished_state.get("FinishedAt"), "pid": lease.identity["pid_birth"]["pid"], "started_at": lease.identity["pid_birth"]["started_at"], "pid_birth_state": lease.identity["pid_birth"]["state"]}
        lease.identity["container_exit"] = container_exit
        if not lifecycle_witness_valid(container_exit):
            raise RuntimeError("container_exit_unobserved")
        report["lifecycle"] = {"pid_birth": "OBSERVED", "container_exit": "OBSERVED" if container_exit["status"] in {"exited", "dead"} and isinstance(container_exit["returncode"], int) and container_exit["exited_at"] else "UNPROVEN"}
        report["uid_gid"] = "NONZERO_MATCHED" if host_uid > 0 and host_gid > 0 else "UNPROVEN"
        report["bootstrap"] = parse_bootstrap_witness(combined_log, expected_uid=host_uid, expected_gid=host_gid)
        report["capture"] = {"complete": capture_complete, "stdout_eof": capture_complete, "stderr_eof": capture_complete, "stdout_bytes": len(outb), "stderr_bytes": len(errb), "stdout_sha256": hashlib.sha256(outb).hexdigest(), "stderr_sha256": hashlib.sha256(errb).hexdigest()}
        report["effect_flags"]["benchmark_test"] = "SUCCEEDED" if capture_complete else "FAILED"; report["parsed_counts"] = {"parsed": len(parsed), "required": report["control_counts"]["required_total"]}; report["stage"] = "cleanup"; report["effect_flags"]["cleanup"] = "IN_PROGRESS"
        bootstrap = report["bootstrap"]
        rm = run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "rm", "-f", actual], timeout=30, env=env); absent = not run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "container", "ls", "-a", "--no-trunc", "--filter", "id=" + actual, "--format", "{{.ID}}"], timeout=30, env=env).stdout.strip(); report["cleanup"] = {"remove_returncode": rm.returncode, "container_absent": absent}; report["effect_flags"]["cleanup"] = "SUCCEEDED" if absent else "UNKNOWN"
        if not absent or not capture_complete: raise RuntimeError("cleanup_or_capture_unproven")
        accounting = validate_accounting(expected_ids=private["FAIL_TO_PASS"] + private["PASS_TO_PASS"], observed=parsed, stage=report["stage"], effect_flags=report["effect_flags"], container_exit=container_exit, uid=host_uid, gid=host_gid, bootstrap=bootstrap, input_owned=input_owned, temp_owned=temp_owned, input_readback=input_readback, temp_readback=temp_readback)
        report["accounting"] = {key: value for key, value in accounting.items() if key != "status"}
        report["status"] = "UNTREATED_CONTROL_COMPLETE" if accounting["status"] == "VALID_BENCHMARK_EVIDENCE" else accounting["status"]
        envelope = emit_envelope([raw_out, raw_err], report, work); ep = envelope.get("payload") or {}; evidence = {"retained": envelope.get("status") == "OPAQUE_EVIDENCE_READY", "status": envelope.get("status"), "export_bytes": envelope.get("export_bytes", 0), "export_cap_bytes": EXPORT_CAP, "ciphertext_sha256": ep.get("ciphertext_sha256"), "wrapped_key_sha256": ep.get("wrapped_key_sha256"), "raw_logs_complete": ep.get("raw_logs_complete")}; report["encrypted_evidence"] = {key: value for key, value in evidence.items() if key != "retained"}
        final_accounting = validate_accounting(expected_ids=private["FAIL_TO_PASS"] + private["PASS_TO_PASS"], observed=parsed, stage=report["stage"], effect_flags=report["effect_flags"], container_exit=container_exit, uid=host_uid, gid=host_gid, bootstrap=bootstrap, input_owned=input_owned, temp_owned=temp_owned, input_readback=input_readback, temp_readback=temp_readback, encrypted_evidence=evidence)
        if final_accounting["status"] != "VALID_BENCHMARK_EVIDENCE": report["status"] = final_accounting["status"]; report["accounting"] = {key: value for key, value in final_accounting.items() if key != "status"}
        if envelope["status"] != "OPAQUE_EVIDENCE_READY": report["status"] = envelope["status"]
        else: print("GLEE_OPAQUE_EVIDENCE_B64=" + envelope["envelope_b64"])
        print("GLEE_SANITIZED_RESULT=" + json.dumps(report, sort_keys=True)); return 0 if report["status"] == "UNTREATED_CONTROL_COMPLETE" else 2
    except Exception as exc:
        detail = str(exc) or type(exc).__name__
        if detail not in SAFE_FAILURE_REASONS and not detail.startswith("image_predicate_failed:"):
            detail = type(exc).__name__
        report["status"] = "UNKNOWN_HELD"; report["failure_reason"] = f"{report.get('stage', 'unknown')}:{detail}"; report["error_type"] = type(exc).__name__
        for key, value in list(report["effect_flags"].items()):
            if value == "IN_PROGRESS": report["effect_flags"][key] = "UNKNOWN"
        cleanup_proven = False
        if actual and docker and cfg:
            try:
                run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "rm", "-f", actual], timeout=30, env=env)
                absent = not run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "container", "ls", "-a", "--no-trunc", "--filter", "id=" + actual, "--format", "{{.ID}}"], timeout=30, env=env).stdout.strip()
                report["cleanup_on_error"] = {"container_absent": absent}
                cleanup_proven = absent
            except Exception:
                report["cleanup_on_error"] = {"status": "UNKNOWN_HELD", "cid_sha256": hashlib.sha256(actual.encode()).hexdigest()}
            if not cleanup_proven:
                hold = retain_unknown_hold(root, cid=actual, nonce=lease.identity.get("nonce", "")); report["unknown_hold"] = {"status": "UNKNOWN_HELD", "custody": "LOCAL_0700", "cid_sha256": hashlib.sha256(actual.encode()).hexdigest(), "nonce_sha256": hashlib.sha256(lease.identity.get("nonce", "").encode()).hexdigest()}; root = hold
        print("GLEE_SANITIZED_RESULT=" + json.dumps(report, sort_keys=True)); return 2
    finally:
        if root.exists() and not root.name.startswith("glee-praisonai-unknown-held-"):
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
