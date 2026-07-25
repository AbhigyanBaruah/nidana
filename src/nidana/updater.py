"""Securely download and atomically install a signed NIDANA index."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from .indexer import atomic_write_json
from .matcher import _load_index


DEFAULT_INDEX_URL = (
    "https://raw.githubusercontent.com/nidana-project/"
    "nidana/main/nidana.index.json"
)


def update_index(
    url: str,
    output: Path,
    pubkey: Path | bytes | None = None,
) -> int:
    """Download, verify, and atomically install a signed index."""

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.download.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            request = Request(
                url,
                headers={"User-Agent": "nidana-updater/1"},
            )
            with urlopen(request, timeout=30) as response:
                while chunk := response.read(1024 * 1024):
                    temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())

        # Verification happens while the download is still temporary. The
        # existing destination is untouched on every failure path.
        _load_index(temporary_path, pubkey)
        with temporary_path.open("r", encoding="utf-8") as index_file:
            payload = json.load(index_file)
        entry_count = len(payload["entries"])
        atomic_write_json(output, payload)
        return entry_count
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()
