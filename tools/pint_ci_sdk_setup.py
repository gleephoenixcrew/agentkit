#!/usr/bin/env python3
"""Bounded, exact-wheel SDK setup used by the manual Pint CI launcher.

All subprocess calls use argv vectors; no shell quoting is involved.  The
wheel is fetched and hashed before pip or any pyarrow import.  Installation is
targeted to the owned temporary SDK site, never the host/global interpreter.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.request

from verify_pinned_wheel import (
    PYARROW_VERSION,
    PYARROW_WHEEL_SHA256,
    PYARROW_WHEEL_URL,
    WheelHashError,
    verify_wheel,
)
from public_contract_preflight import DEFAULT_PUBLIC_CONTRACT, PublicContractError, verify_public_contract

MAX_WHEEL_BYTES = 512 * 1024 * 1024
WHEEL_NAME = "pyarrow-26.0.1-cp312-cp312-manylinux_2_28_x86_64.whl"


class SDKSetupError(RuntimeError):
    """Raised before install/import when the bounded SDK preconditions fail."""


def verify_interpreter(*, executable: str = "/usr/bin/python3") -> None:
    if sys.executable != executable:
        raise SDKSetupError("sdk_interpreter_path_mismatch")
    if sys.version_info[:2] != (3, 12):
        raise SDKSetupError("sdk_interpreter_abi_mismatch")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise SDKSetupError("sdk_architecture_mismatch")


def fetch_wheel(destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = urllib.request.Request(PYARROW_WHEEL_URL, headers={"User-Agent": "GLEE-pint-ci-sdk/1"})
    total = 0
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as stream:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_WHEEL_BYTES:
                raise SDKSetupError("sdk_wheel_transfer_cap_exceeded")
            stream.write(chunk)
    destination.chmod(0o600)


def install_verified_wheel(
    wheel: Path,
    site_dir: Path,
    *,
    runner=subprocess.run,
    python: str = "/usr/bin/python3",
) -> None:
    """Verify bytes, then install only the verified wheel into site_dir."""
    # This ordering is a security boundary: mismatch means runner is untouched.
    verify_wheel(wheel, expected_sha256=PYARROW_WHEEL_SHA256)
    site_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = runner(
        [python, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir",
         "--no-index", "--no-deps", "--target", str(site_dir), str(wheel)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SDKSetupError("sdk_pip_install_failed")


def import_check(site_dir: Path, *, runner=subprocess.run, python: str = "/usr/bin/python3") -> None:
    result = runner(
        [python, "-c", "import pyarrow; assert pyarrow.__version__ == \"26.0.1\""],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(site_dir), "LANG": "C.UTF-8"},
    )
    if result.returncode != 0:
        raise SDKSetupError("sdk_import_version_check_failed")


def setup_sdk(site_dir: Path, wheel_dir: Path, *, runner=subprocess.run, python: str = "/usr/bin/python3",
              public_contract: Path = DEFAULT_PUBLIC_CONTRACT) -> dict[str, str]:
    # Direct helper invocation is fail-closed before interpreter checks,
    # temporary-site creation, wheel download, pip, or SDK import.
    verify_public_contract(public_contract)
    verify_interpreter(executable=python)
    wheel = wheel_dir / WHEEL_NAME
    fetch_wheel(wheel)
    install_verified_wheel(wheel, site_dir, runner=runner, python=python)
    import_check(site_dir, runner=runner, python=python)
    return {"status": "SDK_VERIFIED", "version": PYARROW_VERSION, "wheel_sha256": PYARROW_WHEEL_SHA256,
            "site_dir": str(site_dir)}


def main() -> int:
    parser = argparse.ArgumentParser(description="bounded exact pyarrow SDK setup")
    parser.add_argument("--site-dir", type=Path, required=True)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--public-contract", type=Path, default=DEFAULT_PUBLIC_CONTRACT)
    args = parser.parse_args()
    try:
        result = setup_sdk(args.site_dir, args.wheel_dir, public_contract=args.public_contract)
    except (OSError, SDKSetupError) as exc:
        print(f"SDK_SETUP_FAILED:{exc}")
        return 2
    print(f"SDK_VERIFIED:pyarrow=={result['version']}:sha256={result['wheel_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
