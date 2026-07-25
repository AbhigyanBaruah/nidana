"""Build and persist a local NIDANA vector index."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .embed import VECTOR_DIMENSION, vectorize_function


INDEX_VERSION = 1


def _fallback_record(path: Path) -> dict[str, Any]:
    """Create a deterministic CFG-like record for non-radare2 inputs."""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = path.name

    return {
        "name": path.name,
        "addr": 0,
        "blocks": [
            {
                "addr": 0,
                "esil_ops": text.splitlines()[:256] or [path.name],
                "outgoing_edges": [],
            }
        ],
    }


def _extract_records(path: Path, r2_executable_path: str) -> list[dict[str, Any]]:
    """Extract CFG records from one item, falling back for source files."""

    try:
        from nidana import stream_functions

        return [
            {
                "name": function.name,
                "addr": function.addr,
                "analysis_incomplete": function.analysis_incomplete,
                "blocks": [
                    {
                        "addr": block.addr,
                        "esil_ops": block.esil_ops,
                        "outgoing_edges": block.outgoing_edges,
                    }
                    for block in function.blocks
                ],
            }
            for function in stream_functions(
                str(path),
                r2_executable_path,
            )
        ]
    except Exception:
        return [_fallback_record(path)]


def _source_items(source: Path) -> list[Path]:
    """Return regular files below a source path in stable order."""

    if source.is_file():
        return [source]
    if source.is_dir():
        return sorted(
            path for path in source.rglob("*") if path.is_file()
        )
    raise FileNotFoundError(f"source not found: {source}")


def build_index(
    source: Path,
    cve: str,
    output: Path,
    r2_executable_path: str = "radare2",
    severity: str = "high",
) -> int:
    """Extract, embed, and atomically save reference vectors."""

    items = _source_items(source)
    entries: list[dict[str, Any]] = []

    for item in items:
        for record in _extract_records(item, r2_executable_path):
            vector = vectorize_function(record)
            entries.append(
                {
                    "cve": cve,
                    "severity": severity,
                    "metadata": {
                        "source": str(item),
                        "name": record.get("name", item.name),
                        "addr": record.get("addr", 0),
                    },
                    "vector": vector,
                }
            )

    payload = {
        "version": INDEX_VERSION,
        "dimension": VECTOR_DIMENSION,
        "metric": "cosine",
        "entries": entries,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary, separators=(",", ":"))
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    return len(entries)
