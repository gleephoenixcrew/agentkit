#!/usr/bin/env python3
"""Public Pint collect-only preflight.

This diagnostic binds only a public pinned image and an exact BASE git archive.
It never reads a private Parquet shard, test patch, solution patch, original
test command, or benchmark result.  The container runs pytest collection only;
the emitted record contains aggregate count/errors/exit/header evidence and no
test names.
"""
from __future__ import annotations

import argparse
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
import time

BASE = "f4aa63eb23a22cedb5f90d7bc8934efba26538c4"
IMAGE_REPO = "starryzhang/sweb.eval.x86_64.hgrecco_1776_pint-2108"
IMAGE_MANIFEST = "sha256:1a60490322ba75d99032b9981322a099a49eb1abf3481695acbed0e6a539d015"
IMAGE_CONFIG = "sha256:50a4e62526c6212b7abbf837b7d35fe8356b80f5bc8ba3529cd6cd7dc5b73552"
IMAGE_DIFF_IDS = [
    "sha256:185e04da9d947141fd703dbf36361bdc2ff77cc27cbf500fb9f4881cb5ddbe95",
    "sha256:607ddfe5f3c3f9e9df2b45f6275ad18bc76e49fdebcf0777c1c02c66f5012956",
    "sha256:0dd5860cbc60e77cc364ce36be1a9055d4139f2123324e14f756af1af719ffb0",
    "sha256:08e14ec5b7497da231d70d47d1d80440ba7d9997d43c0796a8394923bbc98183",
    "sha256:a957db1d68d629b71168e4592e1b3882b5718c00ed87b5df6123c9030bcd1ad2",
    "sha256:c1eb2b22a626daba2e21f42efbf50ac14e27c7aa8cdc0bbfc62975698cc1080a",
    "sha256:e6ba6b8b18c11c430a1feb747e05461506d384480779ee6565246cfff96cc56d",
    "sha256:1a5a95f7b7504ed05b8420c35edc8c73adab4a9e76e3ebc2f89f378843aed003",
]
DOCKER_ROOT_FREE_FLOOR_BYTES = 3_873_469_260
DESKTOP_RAM_RESERVE_BYTES = 8 * 1024**3
PARENT_MEMORY_BYTES = 512 * 1024**2
DOCKER_MEMORY_BYTES = 2 * 1024**3
TIMEOUT_SECONDS = 600
PARENT_RUNTIME_SECONDS = 900
PIDS_LIMIT = 64
TMP_MIB, TESTBED_MIB = 256, 1024
RAW_CAPTURE_CAP_BYTES = 8 * 1024 * 1024


class PreflightError(RuntimeError):
    pass


def run(argv: list[str], *, timeout: float = 30, input_bytes: bytes | None = None,
        cwd: str | None = None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
           "HOME": os.environ.get("RUNNER_TEMP", "/tmp")}
    return subprocess.run(argv, timeout=timeout, input=input_bytes,
                          capture_output=True, cwd=cwd, env=env, check=False)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_parent_budget() -> dict:
    try:
        line = next(x for x in Path("/proc/self/cgroup").read_text().splitlines() if x.startswith("0::"))
        rel = line.split(":", 2)[2].strip().lstrip("/")
        scope = Path("/sys/fs/cgroup") / rel
        cpu = (scope / "cpu.max").read_text().split()
        memory = (scope / "memory.max").read_text().strip()
        swap = (scope / "memory.swap.max").read_text().strip()
        pids = (scope / "pids.max").read_text().strip()
        controllers = (scope / "cgroup.controllers").read_text().split()
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": type(exc).__name__}
    if not all(item in controllers for item in ("cpu", "memory", "pids")):
        return {"status": "UNSUPPORTED_PARENT_CONTROL", "reason": "required_controller_missing"}
    if cpu != ["100000", "100000"] or memory != str(PARENT_MEMORY_BYTES) or swap != "0" or pids != str(PIDS_LIMIT):
        return {"status": "PARENT_POLICY_MISMATCH", "cpu": cpu, "memory": memory, "swap": swap, "pids": pids}
    return {"status": "PARENT_BUDGET_VERIFIED", "cpu_cores": 1, "memory_bytes": PARENT_MEMORY_BYTES, "swap_bytes": 0, "pids": PIDS_LIMIT}


def verify_ram() -> dict:
    try:
        values = {line.split(":", 1)[0]: int(line.split()[1]) * 1024
                  for line in Path("/proc/meminfo").read_text().splitlines() if ":" in line}
        available = values["MemAvailable"]
    except (OSError, KeyError, ValueError, IndexError) as exc:
        return {"status": "RAM_UNOBSERVED", "reason": type(exc).__name__}
    required = DESKTOP_RAM_RESERVE_BYTES + PARENT_MEMORY_BYTES + DOCKER_MEMORY_BYTES
    return {"status": "RAM_RESERVE_VERIFIED" if available >= required else "RAM_RESERVE_INSUFFICIENT",
            "available_bytes": available, "required_bytes": required,
            "desktop_reserve_bytes": DESKTOP_RAM_RESERVE_BYTES}


def verify_storage(docker: str) -> dict:
    result = run([docker, "info", "--format", "{{json .}}"], timeout=30)
    if result.returncode != 0:
        return {"status": "DOCKER_ROOT_UNOBSERVED", "reason": "docker_info_failed"}
    try:
        root = Path(json.loads(result.stdout.decode())["DockerRootDir"])
        free = shutil.disk_usage(root).free
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return {"status": "DOCKER_ROOT_UNOBSERVED", "reason": type(exc).__name__}
    return {"status": "DOCKER_ROOT_READY" if free >= DOCKER_ROOT_FREE_FLOOR_BYTES else "DOCKER_ROOT_INSUFFICIENT",
            "free_bytes": free, "required_free_bytes": DOCKER_ROOT_FREE_FLOOR_BYTES,
            "desktop_ram_reserve_gib": 8}


def verify_archive(archive: Path) -> dict:
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size <= 0:
        raise PreflightError("base_archive_missing_or_invalid")
    result = run(["git", "get-tar-commit-id"], timeout=30, input_bytes=archive.read_bytes(), cwd="/")
    observed = result.stdout.decode().strip()
    if result.returncode != 0 or observed != BASE:
        raise PreflightError("base_archive_commit_mismatch")
    return {"status": "BASE_ARCHIVE_VERIFIED", "base_commit": observed,
            "archive_bytes": archive.stat().st_size, "archive_sha256": sha(archive),
            "get_tar_commit_id_cwd": "/"}


def verify_image(docker: str) -> dict:
    reference = IMAGE_REPO + "@" + IMAGE_MANIFEST
    result = run([docker, "image", "inspect", reference], timeout=30)
    if result.returncode != 0:
        raise PreflightError("pinned_public_image_unavailable")
    rows = json.loads(result.stdout.decode())
    if not isinstance(rows, list) or len(rows) != 1:
        raise PreflightError("image_inspect_cardinality")
    row = rows[0]
    repo_ok = any(IMAGE_MANIFEST in item for item in (row.get("RepoDigests") or []))
    diff_ok = (row.get("RootFS") or {}).get("Layers") == IMAGE_DIFF_IDS
    identity_ok = row.get("Id") in {IMAGE_MANIFEST, IMAGE_CONFIG}
    if not (repo_ok and diff_ok and identity_ok):
        raise PreflightError("public_image_identity_or_layers_mismatch")
    return {"status": "PUBLIC_IMAGE_VERIFIED", "manifest": IMAGE_MANIFEST,
            "configuration": IMAGE_CONFIG, "diff_id_count": len(IMAGE_DIFF_IDS),
            "repo_digest_match": repo_ok, "layers_match": diff_ok,
            "identity": row.get("Id")}


def validate_container(row: dict, *, cid: str, name: str, nonce: str, uid: int, gid: int) -> None:
    config, host = row.get("Config") or {}, row.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    if row.get("Id") != cid or config.get("User") != f"{uid}:{gid}" or config.get("WorkingDir") != "/testbed":
        raise PreflightError("container_identity_or_workdir_mismatch")
    if labels.get("glee.owner") != "sanji" or labels.get("glee.qualifier") != "pint-public-collection" or labels.get("glee.name") != name or labels.get("glee.nonce") != nonce:
        raise PreflightError("container_owner_nonce_mismatch")
    if (host.get("Memory") != DOCKER_MEMORY_BYTES or host.get("MemorySwap") != DOCKER_MEMORY_BYTES
            or host.get("NanoCpus") != 1_000_000_000 or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True or host.get("PidsLimit") != PIDS_LIMIT
            or host.get("Privileged") is True or "ALL" not in (host.get("CapDrop") or [])
            or host.get("CapAdd") or not any(str(x).split(":", 1)[0] == "no-new-privileges" for x in (host.get("SecurityOpt") or []))):
        raise PreflightError("container_resource_policy_mismatch")
    tmpfs = host.get("Tmpfs") or {}
    for destination, size in (("/tmp", f"{TMP_MIB}m"), ("/testbed", f"{TESTBED_MIB}m")):
        values = tmpfs.get(destination); values = values if isinstance(values, list) else [values]
        if not any(isinstance(x, str) and f"size={size}" in x and f"uid={uid}" in x and f"gid={gid}" in x for x in values):
            raise PreflightError("tmpfs_policy_or_ownership_mismatch")
    if not any(m.get("Destination") == "/input" and m.get("Type") == "bind" and m.get("RW") is False for m in (row.get("Mounts") or [])):
        raise PreflightError("readonly_archive_mount_missing")


def sanitize_output(raw: bytes) -> dict:
    if len(raw) > RAW_CAPTURE_CAP_BYTES:
        raise PreflightError("collection_output_cap_exceeded")
    text = raw.decode("utf-8", "replace")
    collected = re.findall(r"collected\s+(\d+)\s+items?", text, flags=re.I)
    errors = len(re.findall(r"^ERROR(?:\s|$)", text, flags=re.M))
    headers = [line for line in text.splitlines() if re.match(r"^(platform|rootdir|plugins):", line)]
    return {"collected_count": int(collected[-1]) if collected else 0,
            "collection_error_lines": errors, "header_present": bool(headers),
            "header_sha256": hashlib.sha256("\n".join(headers).encode()).hexdigest() if headers else None}


def cleanup(docker: str, cid: str, root: Path, *, rm_result: subprocess.CompletedProcess | None = None) -> dict:
    rm = rm_result or run([docker, "rm", "-f", cid], timeout=30)
    listed = run([docker, "container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"], timeout=30)
    absent = listed.returncode == 0 and not listed.stdout.strip()
    record = {"remove_returncode": rm.returncode, "list_returncode": listed.returncode,
              "container_absent": absent}
    if absent:
        try:
            root.rmdir()
        except OSError:
            pass
        return record
    custody = root / "UNKNOWN_HELD.json"
    custody.write_text(json.dumps({"schema": "glee.pint.public_collection.unknown_hold.v1",
                                   "status": "UNKNOWN_HELD",
                                   "cid_sha256": hashlib.sha256(cid.encode()).hexdigest(),
                                   "nonce_bound": True}, sort_keys=True) + "\n")
    custody.chmod(0o600)
    record["status"] = "UNKNOWN_HELD"
    record["custody"] = str(custody)
    return record


def run_preflight(*, image: str, archive: Path, docker: str, output: Path) -> dict:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise PreflightError("unsupported_runner")
    parent = verify_parent_budget()
    if parent["status"] != "PARENT_BUDGET_VERIFIED":
        raise PreflightError("parent_budget_not_verified")
    ram = verify_ram()
    if ram["status"] != "RAM_RESERVE_VERIFIED":
        raise PreflightError("ram_reserve_not_verified")
    storage = verify_storage(docker)
    if storage["status"] != "DOCKER_ROOT_READY":
        raise PreflightError("docker_root_not_ready")
    source = verify_archive(archive)
    image_observation = verify_image(docker)
    uid, gid = os.getuid(), os.getgid()
    if uid == 0 or gid == 0:
        raise PreflightError("nonroot_runner_required")
    output = output.resolve()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = output.parent / (output.stem + "-custody")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = "glee-pint-public-collection-" + secrets.token_hex(8)
    nonce = secrets.token_hex(16); cid = None; cleanup_record = None
    command = ("set -euo pipefail; test \"$(id -u)\" = \"%s\"; test \"$(id -g)\" = \"%s\"; "
               "test \"$(stat -c '%%u:%%g' /testbed)\" = \"%s:%s\"; "
               "test \"$(stat -c '%%u:%%g' /tmp)\" = \"%s:%s\"; "
               "rm -rf /testbed/* /testbed/.[!.]* /testbed/..?* 2>/dev/null || true; "
               "tar -xf /input/base_commit.tar -C /testbed; "
               "git -c safe.directory=/testbed -C /testbed init -q; "
               "git -c safe.directory=/testbed -C /testbed add -A; "
               "git -c safe.directory=/testbed -C /testbed -c user.name='GLEE public preflight' -c user.email='preflight@invalid' commit -qm base; "
               "printf 'PREFLIGHT bootstrap=ok\\n'; set +e; "
               "python -m pytest --collect-only -q -p no:cacheprovider >/tmp/collect.txt 2>&1; rc=$?; "
               "count=$(grep -Eo 'collected [0-9]+ items?' /tmp/collect.txt | tail -n 1 | awk '{print $2}'); "
               "errors=$(grep -c -E '^ERROR( |$)' /tmp/collect.txt || true); "
               "headers=$(grep -E '^(platform|rootdir|plugins):' /tmp/collect.txt | sha256sum | awk '{print $1}'); "
               "printf 'PREFLIGHT collect_exit=%%s\\nPREFLIGHT collected=%%s\\nPREFLIGHT error_lines=%%s\\nPREFLIGHT header_sha256=%%s\\n' \"$rc\" \"${count:-0}\" \"$errors\" \"$headers\"; exit 0" % (uid, gid, uid, gid, uid, gid))
    args = [docker, "create", "--pull=never", "--name", name, "--label", "glee.owner=sanji",
            "--label", "glee.qualifier=pint-public-collection", "--label", "glee.name=" + name,
            "--label", "glee.nonce=" + nonce, "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
            "--memory=2g", "--memory-swap=2g", "--cpus=1", "--user=%s:%s" % (uid, gid),
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777,uid=%s,gid=%s" % (uid, gid),
            "--tmpfs=/testbed:rw,noexec,nosuid,nodev,size=1024m,mode=1777,uid=%s,gid=%s" % (uid, gid),
            "--mount", "type=bind,src=%s,dst=/input/base_commit.tar,readonly" % archive.resolve(),
            "--workdir=/testbed", "--entrypoint=/bin/bash", image, "-lc", command]
    try:
        created = run(args, timeout=30)
        if created.returncode != 0 or not created.stdout.strip():
            raise PreflightError("container_create_failed")
        cid = created.stdout.decode().strip()
        inspected = run([docker, "inspect", cid], timeout=30)
        if inspected.returncode != 0:
            raise PreflightError("container_inspect_failed")
        validate_container(json.loads(inspected.stdout.decode())[0], cid=cid, name=name, nonce=nonce, uid=uid, gid=gid)
        started = run([docker, "start", "--attach", cid], timeout=TIMEOUT_SECONDS)
        if len(started.stdout) + len(started.stderr) > RAW_CAPTURE_CAP_BYTES:
            raise PreflightError("collection_output_cap_exceeded")
        markers = sanitize_output(started.stdout + b"\n" + started.stderr)
        cleanup_record = cleanup(docker, cid, root)
        if not cleanup_record.get("container_absent"):
            raise PreflightError("cleanup_absence_unproven")
        result = {"schema": "glee.pint.public_collection_preflight.v1", "status": "PUBLIC_COLLECTION_COMPLETE",
                  "docker_execution": True, "benchmark_grade": False, "base_source": source,
                  "image": image_observation, "parent": parent, "ram": ram, "storage": storage,
                  "policy": {"docker_cpu": 1, "docker_memory_bytes": DOCKER_MEMORY_BYTES, "swap": 0,
                             "pids": PIDS_LIMIT, "network": "none", "readonly_rootfs": True,
                             "cap_drop": "ALL", "tmp_mib": TMP_MIB, "testbed_mib": TESTBED_MIB,
                             "uid_gid": f"{uid}:{gid}"},
                  "collect_only": {**markers, "exit_code": started.returncode,
                                   "command": "python -m pytest --collect-only -q -p no:cacheprovider",
                                   "names_emitted": False},
                  "cleanup": cleanup_record, "provider_calls": 0}
        if markers["collection_error_lines"] or started.returncode != 0:
            result["status"] = "PUBLIC_COLLECTION_ERRORS"
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n"); output.chmod(0o600)
        return result
    except Exception:
        if cid:
            try:
                cleanup_record = cleanup(docker, cid, root)
            except Exception:
                cleanup_record = {"status": "UNKNOWN_HELD"}
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=IMAGE_REPO + "@" + IMAGE_MANIFEST)
    parser.add_argument("--base-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("PUBLIC_COLLECTION_RESULT.json"))
    parser.add_argument("--docker", default=shutil.which("docker") or "docker")
    args = parser.parse_args(argv)
    try:
        result = run_preflight(image=args.image, archive=args.base_archive, docker=args.docker, output=args.output)
    except Exception as exc:
        result = {"schema": "glee.pint.public_collection_preflight.v1", "status": "PUBLIC_COLLECTION_BLOCKED",
                  "reason": type(exc).__name__, "provider_calls": 0, "docker_execution": False}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n"); args.output.chmod(0o600)
        print(json.dumps(result, sort_keys=True)); return 2
    print(json.dumps({"status": result["status"], "collected_count": result["collect_only"]["collected_count"],
                      "collection_error_lines": result["collect_only"]["collection_error_lines"],
                      "exit_code": result["collect_only"]["exit_code"], "benchmark_grade": False}, sort_keys=True))
    return 0 if result["status"] == "PUBLIC_COLLECTION_COMPLETE" else 4


if __name__ == "__main__":
    raise SystemExit(main())
