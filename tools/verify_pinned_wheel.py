#!/usr/bin/env python3
"""Fail-closed verification for the reviewed Pint SDK wheel.

This helper is intentionally stdlib-only.  It hashes a wheel before pip or any
SDK import is attempted; a mismatch raises and returns nonzero without calling
pip.  It never downloads, installs, imports, or prints wheel contents.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

PYARROW_VERSION = "26.0.1"
PYARROW_WHEEL_SHA256 = "c718bf97a92a6dea97fd1062c3b9f9e2e83cb9cc926e752289fa4ffff41738f9"
PYARROW_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/d3/79/e2fc9b1317b7a21e7bcd57eb035cac3fe72f47af3efe2ec3b4dea9a08a04/"
    "pyarrow-26.0.1-cp312-cp312-manylinux_2_28_x86_64.whl"
)


class WheelHashError(RuntimeError):
    """Raised when the exact reviewed wheel cannot be proven."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_wheel(path: Path, *, expected_sha256: str = PYARROW_WHEEL_SHA256) -> str:
    """Return the verified digest, refusing missing or mismatched bytes."""
    if not path.is_file():
        raise WheelHashError("pyarrow_wheel_missing")
    observed = sha256_file(path)
    if observed != expected_sha256:
        raise WheelHashError("pyarrow_wheel_sha256_mismatch")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description="verify the pinned Pint pyarrow wheel")
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    try:
        observed = verify_wheel(args.wheel)
    except (OSError, WheelHashError) as exc:
        print(f"WHEEL_VERIFICATION_FAILED:{exc}")
        return 2
    print(f"WHEEL_VERIFIED:pyarrow=={PYARROW_VERSION}:sha256={observed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
