#!/usr/bin/env python3
"""Fail-closed public resource-contract byte and frame verification.

The JSON verified here is a deliberately public projection.  It contains no
private row, patch, command, oracle, examiner, solution, or credential data.
The transformed private-contract SHA is opaque: it is compared, never opened
or expanded.  This module is stdlib-only and performs no subprocess/network
operation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PUBLIC_CONTRACT_SHA256 = "0aaed86a04d49141a8f8b7d8b479be1038c0110d1d40f82f0cd97dea82cbc485"
TRANSFORMED_PRIVATE_CONTRACT_SHA256 = "d533b15fc6b4d207f7d31b0f21ed42ae2dca9350c1983d223a1a7622d4798697"
DEFAULT_PUBLIC_CONTRACT = Path(__file__).resolve().parents[1] / "PINT_PUBLIC_RUNTIME_RESOURCE_CONTRACT.json"

EXPECTED_PINS = {
    "dataset_revision": "babb27e45e072219195db7a744bbf0d3c1a36e56",
    "absolute_row": 1801,
    "first_shard_rows": 944,
    "local_row": 857,
    "public_row_sha256": "856b0669fa80d7f1286d474dcde4be357bca51b85314d3aff29dfa7779836e98",
    "parquet_sha256": "b8cd02f881baf1621b6ed17a2980f82a002d7e895c45c8653b0b696467dbf72e",
    "parquet_size": 49856992,
    "base_commit": "f4aa63eb23a22cedb5f90d7bc8934efba26538c4",
    "image_repo": "starryzhang/sweb.eval.x86_64.hgrecco_1776_pint-2108",
    "image_manifest": "sha256:1a60490322ba75d99032b9981322a099a49eb1abf3481695acbed0e6a539d015",
    "pyarrow_version": "26.0.1",
    "pyarrow_wheel_url": "https://files.pythonhosted.org/packages/d3/79/e2fc9b1317b7a21e7bcd57eb035cac3fe72f47af3efe2ec3b4dea9a08a04/pyarrow-26.0.1-cp312-cp312-manylinux_2_28_x86_64.whl",
    "pyarrow_wheel_sha256": "c718bf97a92a6dea97fd1062c3b9f9e2e83cb9cc926e752289fa4ffff41738f9",
}
EXPECTED_RESOURCE_FRAME = {
    "docker": {
        "cpu_cores": 1,
        "memory_mib": 2048,
        "swap_mib": 0,
        "pids_limit": 64,
        "network": "none",
        "readonly_rootfs": True,
        "cap_drop": "ALL",
        "tmpfs": {
            "/testbed": "1024m,rw,noexec,nosuid,nodev",
            "/tmp": "256m,rw,noexec,nosuid,nodev",
        },
    },
    "parent": {"cpu_cores": 1, "memory_mib": 512, "swap_mib": 0, "pids_limit": 64},
    "operation_deadline_seconds": 3600,
    "cleanup_margin_seconds": 120,
    "workflow_minutes": 90,
    "parent_seconds": 5100,
    "job_seconds": 5400,
    "sdk_deadline_seconds": 900,
    "sdk_memory_mib": 768,
    "desktop_ram_reserve_gib": 8,
}
EXPECTED_TRIAL_FENCES = {
    "number": 3,
    "total": 3,
    "historical_original_dispatches": 2,
    "remaining_original_dispatches": 1,
    "automatic_retry": False,
    "reference_allowed": False,
}


class PublicContractError(RuntimeError):
    """Raised before any control effect when public binding is invalid."""


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_public_contract_bytes(raw: bytes, *, expected_sha256: str = PUBLIC_CONTRACT_SHA256) -> dict[str, Any]:
    """Verify exact bytes and all public pins/frame/fences; return parsed data."""
    observed = _digest(raw)
    if observed != expected_sha256:
        raise PublicContractError("public_contract_sha256_mismatch")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublicContractError("public_contract_invalid_json") from exc
    if not isinstance(data, dict) or data.get("schema") != "glee.pint.public_runtime_resource_contract.v1":
        raise PublicContractError("public_contract_schema_mismatch")
    if data.get("status") != "ASSEMBLED_SOURCE_ONLY_HOLD_INDEPENDENT_REVIEW_REQUIRED":
        raise PublicContractError("public_contract_status_mismatch")
    contract = data.get("contract")
    if not isinstance(contract, dict) or contract.get("transformed_private_contract_sha256") != TRANSFORMED_PRIVATE_CONTRACT_SHA256:
        raise PublicContractError("transformed_private_contract_sha256_mismatch")
    pins = data.get("pins")
    if pins != EXPECTED_PINS:
        raise PublicContractError("public_contract_pins_mismatch")
    if data.get("resource_frame") != EXPECTED_RESOURCE_FRAME:
        raise PublicContractError("public_contract_resource_frame_mismatch")
    if data.get("trial_fences") != EXPECTED_TRIAL_FENCES:
        raise PublicContractError("public_contract_trial_fences_mismatch")
    return data


def verify_public_contract(path: Path = DEFAULT_PUBLIC_CONTRACT) -> dict[str, Any]:
    """Read and verify the public projection; never read a private contract."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PublicContractError("public_contract_missing") from exc
    return verify_public_contract_bytes(raw)


def verify_driver_resource_frame(data: dict[str, Any], actual: dict[str, Any]) -> None:
    """Strictly compare supplied driver arguments/constants to public frame."""
    frame = data["resource_frame"]
    for key in ("docker", "parent"):
        if actual[key] != frame[key]:
            raise PublicContractError("driver_resource_frame_mismatch")
    for key in ("operation_deadline_seconds", "cleanup_margin_seconds"):
        if actual[key] != frame[key]:
            raise PublicContractError("driver_deadline_frame_mismatch")


def verify_driver_trial_fences(data: dict[str, Any], actual: dict[str, Any]) -> None:
    """Strictly compare driver trial state to the verified public fences."""
    if actual != data["trial_fences"]:
        raise PublicContractError("driver_trial_fences_mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description="verify the public Pint runtime resource contract")
    parser.add_argument("--contract", type=Path, default=DEFAULT_PUBLIC_CONTRACT)
    args = parser.parse_args()
    try:
        data = verify_public_contract(args.contract)
    except (OSError, PublicContractError) as exc:
        print(f"PUBLIC_CONTRACT_PREFLIGHT_FAILED:{exc}")
        return 2
    print(f"PUBLIC_CONTRACT_VERIFIED:sha256={_digest(args.contract.read_bytes())}:private_sha256={data['contract']['transformed_private_contract_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
