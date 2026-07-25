"""End-to-end extraction test using a small non-x86 cross-compiled binary."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nidana import stream_functions


def _cross_compiler() -> str | None:
    """Find an installed ARM or MIPS cross-compiler."""

    for name in (
        "arm-linux-gnueabi-gcc",
        "arm-linux-gnueabihf-gcc",
        "aarch64-linux-gnu-gcc",
        "mips-linux-gnu-gcc",
    ):
        compiler = shutil.which(name)
        if compiler:
            return compiler
    return None


@pytest.fixture
def cross_compiled_binary(tmp_path: Path) -> Path:
    """Build a tiny branching ARM/MIPS binary when a cross-compiler exists."""

    compiler = _cross_compiler()
    if compiler is None:
        pytest.skip("no ARM/MIPS cross-compiler is installed")

    source = tmp_path / "fixture.c"
    binary = tmp_path / "fixture.bin"
    source.write_text(
        """
        __attribute__((noinline)) int helper(int value) {
            if (value & 1) {
                return value + 3;
            }
            return value - 2;
        }

        int main(void) {
            volatile int result = helper(7);
            return result == 10 ? 0 : 1;
        }
        """,
        encoding="utf-8",
    )

    subprocess.run(
        [
            compiler,
            "-O0",
            "-fno-inline",
            "-g",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def test_stream_functions_extracts_non_x86_binary(
    cross_compiled_binary: Path,
) -> None:
    """Verify real CFG extraction against a cross-compiled binary."""

    r2_executable = os.environ.get("NIDANA_R2") or shutil.which("radare2")
    if r2_executable is None:
        pytest.skip("radare2 is not installed")

    functions = list(
        stream_functions(
            str(cross_compiled_binary),
            r2_executable,
        )
    )

    assert len(functions) > 0
    assert any(len(function.blocks) > 1 for function in functions)
