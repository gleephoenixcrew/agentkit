#!/usr/bin/env python3
"""Portable original cfn-lint untreated-control runner.

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
BASE = "11dc6213168d3d56aff2d244e099bf21a80e64e6"
IMAGE_REPO = "starryzhang/sweb.eval.x86_64.aws-cloudformation_1776_cfn-lint-4197"
IMAGE_MANIFEST = "sha256:a6fa8afccb6bf8e2a1012e0526602a229ec673f06bab0a730740820181069323"
IMAGE_CONFIG = "sha256:1c8f4c34b3b85bff5a7d240b0b75f245a366fe1d8c342c207e09a91576226955"
IMAGE_DIFF_IDS = ["sha256:185e04da9d947141fd703dbf36361bdc2ff77cc27cbf500fb9f4881cb5ddbe95", "sha256:607ddfe5f3c3f9e9df2b45f6275ad18bc76e49fdebcf0777c1c02c66f5012956", "sha256:0dd5860cbc60e77cc364ce36be1a9055d4139f2123324e14f756af1af719ffb0", "sha256:08e14ec5b7497da231d70d47d1d80440ba7d9997d43c0796a8394923bbc98183", "sha256:a957db1d68d629b71168e4592e1b3882b5718c00ed87b5df6123c9030bcd1ad2", "sha256:c1eb2b22a626daba2e21f42efbf50ac14e27c7aa8cdc0bbfc62975698cc1080a", "sha256:e6ba6b8b18c11c430a1feb747e05461506d384480779ee6565246cfff96cc56d", "sha256:46535f8ebfe4ff869831f2192e323c56d81e26f03f9787fb095f3485d3ac3295"]
PARQUET_URL = f"https://huggingface.co/datasets/SWE-bench-Live/SWE-bench-Live/resolve/{REV}/data/full-00001-of-00002.parquet"
PARQUET_SIZE = 49_856_992
PARQUET_SHA = "b8cd02f881baf1621b6ed17a2980f82a002d7e895c45c8653b0b696467dbf72e"
PARQUET_ETAG = '"0c829aa2ca28e41e234497056a74b51c78336f12ec9e4f5adaff4d296046693b"'
PUBLIC_SHA = "2961ab3f896a50530ea899a82c424a43c977f1b0e26d415a57a7d52548679827"
EVALUATOR_SHA = "616c68561863b65ce4ad38b8e3e1d0f79d87774a03054970cb5040272268efe2"
F2P_COUNT, P2P_COUNT = 3, 1601
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


def digest(v) -> str:
    # Match the canonical public-row binder's ASCII-escaped JSON contract.
    return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def run(argv, *, timeout=30, env=None, check=False, text=True):
    safe = env or {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.environ.get("RUNNER_TEMP", "/tmp"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(argv, timeout=timeout, env=safe, capture_output=True, text=text, check=check)


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
    if pf.metadata.num_rows != 944 or pf.num_row_groups != 1:
        raise RuntimeError("parquet_rowgroup_identity_mismatch")
    fields = ("repo", "instance_id", "base_commit", "created_at", "docker_image", "problem_statement", "patch", "test_patch", "test_cmds", "FAIL_TO_PASS", "PASS_TO_PASS", "rebuild_cmds", "log_parser")
    values = {}
    for field in fields:
        for i, batch in enumerate(pf.iter_batches(batch_size=1, row_groups=[0], columns=[field], use_threads=False)):
            if i == 858:
                values[field] = batch.column(0).to_pylist()[0]
                break
        else:
            raise RuntimeError("parquet_target_row_missing")
    if isinstance(values["created_at"], datetime):
        values["created_at"] = values["created_at"].replace(tzinfo=None).isoformat(timespec="seconds")
    public = {k: values[k] for k in ("repo", "instance_id", "base_commit", "created_at", "docker_image", "problem_statement")}
    if digest(public) != PUBLIC_SHA or public["base_commit"] != BASE or public["docker_image"] != IMAGE_REPO:
        raise RuntimeError("public_row_binding_mismatch")
    if values["log_parser"] != "pytest" or len(values["test_cmds"]) != 1 or len(values["rebuild_cmds"]) != 0:
        raise RuntimeError("original_parser_command_binding_mismatch")
    return values


def verify_image(docker: str, cfg: str) -> dict:
    result = run([docker, "--config", cfg, "--host", "unix:///var/run/docker.sock", "image", "inspect", IMAGE_REPO], timeout=30)
    if result.returncode != 0:
        return {"status": "IMAGE_ABSENT", "reason": "image_inspect_failed"}
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
    if not any(IMAGE_MANIFEST in x for x in repo_digests) or identity_mode == "UNSUPPORTED_ID" or rootfs != IMAGE_DIFF_IDS:
        raise RuntimeError("image_identity_or_diffid_mismatch")
    return {"status": "IMAGE_VERIFIED", "repo_digest_match": True, "image_id": image_id, "configuration_digest": config_digest, "identity_mode": identity_mode, "diff_id_count": len(rootfs)}


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
    if labels.get("glee.owner") != "sanji" or labels.get("glee.qualifier") != "cfn-lint" or labels.get("glee.nonce") != nonce or labels.get("glee.name") != name:
        raise RuntimeError("container_owner_nonce_label_mismatch")
    if config.get("User") != f"{uid}:{gid}" or config.get("WorkingDir") != "/testbed":
        raise RuntimeError("container_uid_or_workdir_mismatch")
    if (host.get("Memory") != 2 * 1024**3 or host.get("MemorySwap") != 2 * 1024**3 or host.get("NanoCpus") != 1_000_000_000 or host.get("NetworkMode") != "none" or host.get("ReadonlyRootfs") is not True or host.get("PidsLimit") != 64 or host.get("Privileged") is True or "ALL" not in (host.get("CapDrop") or []) or host.get("CapAdd") or not any(str(x).split(":", 1)[0] == "no-new-privileges" for x in (host.get("SecurityOpt") or []))):
        raise RuntimeError("container_resource_policy_mismatch")
    env = config.get("Env") or []
    if any(any(secret in str(item).split("=", 1)[0].upper() for secret in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "OPENAI", "CODEX_HOME")) for item in env):
        raise RuntimeError("container_credentials_exposed")
    tmpfs = host.get("Tmpfs") or {}
    for destination, size in (("/tmp", "256m"), ("/testbed", "1024m")):
        values = tmpfs.get(destination); values = values if isinstance(values, list) else [values]
        if not any(isinstance(item, str) and all(flag in item for flag in ("rw", "noexec", "nosuid", "nodev", f"size={size}")) for item in values):
            raise RuntimeError("container_tmpfs_policy_mismatch")
    if not any(m.get("Destination") == "/input" and m.get("Type") == "bind" and m.get("RW") is False for m in (row.get("Mounts") or [])):
        raise RuntimeError("container_input_mount_mismatch")


def parse_pytest(log: str) -> dict[str, str]:
    out = {}
    for line in log.splitlines():
        for status in ("FAILED", "PASSED", "SKIPPED", "ERROR", "XFAIL"):
            if line.startswith(status):
                parts = line.replace(" - ", " ").split()
                if len(parts) > 1:
                    out[parts[1]] = "pass" if status in {"PASSED", "XFAIL"} else ("skip" if status == "SKIPPED" else ("fail" if status in {"FAILED", "ERROR"} else status.lower()))
                break
    return out


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
    if len(parsed) != len(private_row["FAIL_TO_PASS"]) + len(private_row["PASS_TO_PASS"]): raise RuntimeError("offline_parser_coverage")
    transport.remove()
    if not transport.absent(): raise RuntimeError("offline_cleanup_absence")
    lease.finish("UNTREATED_EXPECTED_FAILURE_CONTROL")
    return {"status": "PASS", "required_total": len(private_row["FAIL_TO_PASS"]) + len(private_row["PASS_TO_PASS"]), "pid_birth_bound": True, "cleanup_absence_proven": True, "parser": private_row["log_parser"]}


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
    payload = {"schema": "glee.remote.cfn_lint.opaque_evidence.v1", "public_recipient_fingerprint_sha256": "3f687c06feebddfd318e6afad1fc4377be022fe4ba9f9b7b16b0491ce3ff942d", "ciphertext_sha256": hashlib.sha256(cipher.read_bytes()).hexdigest(), "wrapped_key_sha256": hashlib.sha256(wrapped.read_bytes()).hexdigest(), "ciphertext_bytes": cipher.stat().st_size, "wrapped_key_bytes": wrapped.stat().st_size, "raw_logs_complete": capture.get("complete") is True and capture.get("stdout_eof") is True and capture.get("stderr_eof") is True, "stream_eof": {"stdout": capture.get("stdout_eof") is True, "stderr": capture.get("stderr_eof") is True}, "summary": summary}
    envelope = json.dumps(payload, sort_keys=True).encode() + b"\nCIPHERTEXT_B64=" + base64.b64encode(cipher.read_bytes()) + b"\nWRAPPED_KEY_B64=" + base64.b64encode(wrapped.read_bytes())
    if len(envelope) > EXPORT_CAP * 9 // 10:
        return {"status": "UNVERIFIED_EXPORT", "reason": "encrypted_evidence_exceeds_bounded_log_export", "export_bytes": len(envelope), "payload": payload}
    return {"status": "OPAQUE_EVIDENCE_READY", "export_bytes": len(envelope), "payload": payload, "envelope_b64": base64.b64encode(envelope).decode()}


def retain_unknown_hold(root: Path, *, cid: str, nonce: str) -> Path:
    base = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    hold = base / ("glee-cfn-lint-unknown-held-" + secrets.token_hex(8))
    root.rename(hold); hold.chmod(0o700)
    custody = {"schema": "glee.remote.cfn_lint.unknown_hold.v1", "status": "UNKNOWN_HELD", "cid": cid, "nonce": nonce, "operation_root": str(hold), "recovery": "exact CID+nonce required; no replay by name"}
    (hold / "UNKNOWN_HELD.json").write_text(json.dumps(custody, sort_keys=True) + "\n"); (hold / "UNKNOWN_HELD.json").chmod(0o600)
    return hold


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="glee-cfn-untreated-")); root.chmod(0o700)
    lease = Lease(root / "operation", secrets.token_hex(16))
    report = {"schema": "glee.remote.cfn_lint.original_untreated.v1", "status": "STARTING", "stage": "parent_preflight", "failure_reason": None, "effect_flags": {"dataset_fetch": "NOT_STARTED", "image_pull": "NOT_STARTED", "source_fetch": "NOT_STARTED", "container_create": "NOT_STARTED", "container_start": "NOT_STARTED", "benchmark_test": "NOT_STARTED", "cleanup": "NOT_STARTED"}, "instance_id": "aws-cloudformation__cfn-lint-4197", "control_counts": {"FAIL_TO_PASS": F2P_COUNT, "PASS_TO_PASS": P2P_COUNT, "required_total": F2P_COUNT + P2P_COUNT}, "provider_calls": 0, "model_subjects": 0}
    actual = None; docker = None; cfg = None; env = {}
    try:
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
        storage = verify_docker_storage(docker, str(cfg)); report["docker_root_storage"] = storage
        if storage["status"] != "DOCKER_ROOT_STORAGE_VERIFIED": report["status"] = storage["status"]; print(json.dumps(report, sort_keys=True)); return 2
        parquet = work / "full-00001-of-00002.parquet"; report["stage"] = "dataset_fetch"; report["effect_flags"]["dataset_fetch"] = "IN_PROGRESS"
        with urllib.request.urlopen(urllib.request.Request(PARQUET_URL, headers={"User-Agent": "GLEE-remote-cfn-lint-original-control/1"}), timeout=120) as response, parquet.open("wb") as out:
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
        report["effect_flags"]["dataset_fetch"] = "SUCCEEDED"; private = read_private_row(parquet); report["parser"] = private["log_parser"]; report["stage"] = "image_admission"
        image = verify_image(docker, str(cfg))
        if image["status"] == "IMAGE_ABSENT":
            report["effect_flags"]["image_pull"] = "IN_PROGRESS"
            pull = subprocess.run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "pull", "--quiet", IMAGE_REPO + "@" + IMAGE_MANIFEST], env=env, capture_output=True, text=True, timeout=900, check=False)
            if pull.returncode != 0: raise RuntimeError("pinned_image_pull_failed")
            image = verify_image(docker, str(cfg))
            report["effect_flags"]["image_pull"] = "SUCCEEDED"
        report["image"] = {k: image.get(k) for k in ("status", "repo_digest_match", "identity_mode", "configuration_digest", "diff_id_count")}
        if image["status"] != "IMAGE_VERIFIED": raise RuntimeError("pinned_image_not_verified")
        report["stage"] = "source_fetch"; report["effect_flags"]["source_fetch"] = "IN_PROGRESS"; repo = work / "source"; repo.mkdir(mode=0o700)
        run(["git", "init", "-q", str(repo)], timeout=30, check=True); run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/aws-cloudformation/cfn-lint.git"], timeout=30, check=True); run(["git", "-C", str(repo), "fetch", "--depth=1", "origin", BASE], timeout=900, check=True)
        if run(["git", "-C", str(repo), "rev-parse", "FETCH_HEAD"], timeout=30).stdout.strip() != BASE: raise RuntimeError("base_commit_identity_mismatch")
        archive = work / "base_commit.tar"; run(["git", "-C", str(repo), "archive", "--format=tar", BASE, "-o", str(archive)], timeout=300, check=True); report["effect_flags"]["source_fetch"] = "SUCCEEDED"
        input_dir = work / "input"; input_dir.mkdir(mode=0o700)
        shutil.copy2(archive, input_dir / "base_commit.tar"); (input_dir / "test.patch").write_text(private["test_patch"]); (input_dir / "solution.patch").write_text(""); (input_dir / "test_cmd.sh").write_text(" ; ".join(private["test_cmds"]) + "\n")
        for p in input_dir.iterdir(): p.chmod(0o600)
        lease.begin(); report["stage"] = "container_create"; report["effect_flags"]["container_create"] = "IN_PROGRESS"; cid = "glee-cfn-lint-untreated-" + secrets.token_hex(8); nonce = secrets.token_hex(16); lease.identity = {"cid": None, "name": cid, "nonce": nonce}
        args = [docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "create", "--name", cid, "--label", "glee.owner=sanji", "--label", "glee.qualifier=cfn-lint", "--label", "glee.nonce=" + nonce, "--label", "glee.name=" + cid, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=2g", "--memory-swap=2g", "--cpus=1", "--user=%s:%s" % (os.getuid(), os.getgid()), "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777", "--tmpfs=/testbed:rw,noexec,nosuid,nodev,size=1024m,mode=1777", "--mount", "type=bind,src=%s,dst=/input,readonly" % input_dir, "--workdir=/testbed", "--entrypoint=/bin/bash", IMAGE_REPO + "@" + IMAGE_MANIFEST, "-lc", "set -euo pipefail; rm -rf /testbed/* /testbed/.[!.]* /testbed/..?* 2>/dev/null || true; tar -xf /input/base_commit.tar -C /testbed; unset $(compgen -v | grep '^GIT_' || true); git -C /testbed init -q; git -C /testbed add -A; git -c user.name='GLEE control' -c user.email='control@invalid' -c commit.gpgsign=false -C /testbed commit -qm base; git -C /testbed apply --reject --whitespace=nowarn /input/test.patch; bash /input/test_cmd.sh"]
        created = run(args, timeout=30, env=env); 
        if created.returncode != 0: raise RuntimeError("container_create_failed")
        actual = created.stdout.strip(); lease.identity["cid"] = actual; report["effect_flags"]["container_create"] = "SUCCEEDED"; report["stage"] = "container_start"
        inspect = json.loads(run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "inspect", actual], timeout=30, env=env, check=True).stdout)[0]; validate_container_inspect(inspect, cid=actual, name=cid, nonce=nonce, uid=os.getuid(), gid=os.getgid(), image_ids={IMAGE_CONFIG, IMAGE_MANIFEST}); lease.identity["created_pid"] = (inspect.get("State") or {}).get("Pid", 0)
        if lease.identity["created_pid"] != 0: raise RuntimeError("created_pid_not_zero")
        report["effect_flags"]["container_start"] = "IN_PROGRESS"; started = run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "start", actual], timeout=30, env=env)
        if started.returncode != 0: raise RuntimeError("container_start_failed")
        report["effect_flags"]["container_start"] = "SUCCEEDED"; report["stage"] = "benchmark_test"; report["effect_flags"]["benchmark_test"] = "IN_PROGRESS"
        running = json.loads(run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "inspect", actual], timeout=30, env=env, check=True).stdout)[0]; lease.identity["pid_birth"] = {"pid": (running.get("State") or {}).get("Pid"), "started_at": (running.get("State") or {}).get("StartedAt")}
        if not isinstance(lease.identity["pid_birth"]["pid"], int) or lease.identity["pid_birth"]["pid"] <= 0: raise RuntimeError("pid_birth_missing")
        raw_out, raw_err = work / "stdout.raw", work / "stderr.raw"; proc = subprocess.Popen([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "logs", "--follow", actual], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env); outb, errb = proc.communicate(timeout=OP_DEADLINE - CLEANUP_MARGIN); raw_out.write_bytes(outb); raw_err.write_bytes(errb); capture_complete = proc.returncode == 0
        parsed = parse_pytest((outb + b"\n" + errb).decode("utf-8", "replace")); report["capture"] = {"complete": capture_complete, "stdout_eof": capture_complete, "stderr_eof": capture_complete, "stdout_bytes": len(outb), "stderr_bytes": len(errb), "stdout_sha256": hashlib.sha256(outb).hexdigest(), "stderr_sha256": hashlib.sha256(errb).hexdigest()}
        report["effect_flags"]["benchmark_test"] = "SUCCEEDED"; report["parsed_counts"] = {"parsed": len(parsed), "required": F2P_COUNT + P2P_COUNT}; report["stage"] = "cleanup"; report["effect_flags"]["cleanup"] = "IN_PROGRESS"
        rm = run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "rm", "-f", actual], timeout=30, env=env); absent = not run([docker, "--config", str(cfg), "--host", "unix:///var/run/docker.sock", "container", "ls", "-a", "--no-trunc", "--filter", "id=" + actual, "--format", "{{.ID}}"], timeout=30, env=env).stdout.strip(); report["cleanup"] = {"remove_returncode": rm.returncode, "container_absent": absent}; report["effect_flags"]["cleanup"] = "SUCCEEDED" if absent else "UNKNOWN"
        if not absent or not capture_complete: raise RuntimeError("cleanup_or_capture_unproven")
        report["status"] = "UNTREATED_CONTROL_COMPLETE"; envelope = emit_envelope([raw_out, raw_err], report, work); ep = envelope.get("payload") or {}; report["encrypted_evidence"] = {"status": envelope.get("status"), "export_bytes": envelope.get("export_bytes"), "ciphertext_sha256": ep.get("ciphertext_sha256"), "wrapped_key_sha256": ep.get("wrapped_key_sha256"), "raw_logs_complete": ep.get("raw_logs_complete")}
        if envelope["status"] != "OPAQUE_EVIDENCE_READY": report["status"] = envelope["status"]
        else: print("GLEE_OPAQUE_EVIDENCE_B64=" + envelope["envelope_b64"])
        print("GLEE_SANITIZED_RESULT=" + json.dumps(report, sort_keys=True)); return 0 if report["status"] == "UNTREATED_CONTROL_COMPLETE" else 2
    except Exception as exc:
        report["status"] = "UNKNOWN_HELD"; report["failure_reason"] = f"{report.get('stage', 'unknown')}:{type(exc).__name__}"; report["error_type"] = type(exc).__name__
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
                hold = retain_unknown_hold(root, cid=actual, nonce=lease.identity.get("nonce", "")); report["unknown_hold"] = {"path": str(hold), "cid": actual, "nonce": lease.identity.get("nonce", "")}; root = hold
        print("GLEE_SANITIZED_RESULT=" + json.dumps(report, sort_keys=True)); return 2
    finally:
        if root.exists() and not root.name.startswith("glee-cfn-lint-unknown-held-"):
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
