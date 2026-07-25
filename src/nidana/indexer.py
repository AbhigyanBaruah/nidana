"""Build and persist a local NIDANA vector index."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .embed import VECTOR_DIMENSION, vectorize_function


INDEX_VERSION = 1


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Serialize signed index fields deterministically."""

    signed_fields = {
        key: payload.get(key)
        for key in ("version", "dimension", "metric", "entries")
    }
    return json.dumps(
        signed_fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sign_payload(payload: dict[str, Any], signing_key: Path) -> str:
    """Sign canonical payload bytes with an Ed25519 PEM private key."""

    try:
        private_key = serialization.load_pem_private_key(
            signing_key.read_bytes(),
            password=None,
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(
            f"cannot load Ed25519 signing key {signing_key}: {exc}"
        ) from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("signing key is not an Ed25519 private key")

    return b64encode(
        private_key.sign(canonical_payload(payload))
    ).decode("ascii")


def atomic_write_json(output: Path, payload: dict[str, Any]) -> None:
    """Write JSON atomically and durably to the target path."""

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
            json.dump(
                payload,
                temporary,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def _extract_records(path: Path, r2_executable_path: str) -> list[dict[str, Any]]:
    """Extract CFG records from one item using the radare2 bridge."""

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
    signing_key: Path | None = None,
) -> int:
    """Extract, embed, and atomically save reference vectors."""

    items = _source_items(source)
    entries: list[dict[str, Any]] = []
    failed_count = 0

    for item in items:
        try:
            records = _extract_records(item, r2_executable_path)
        except Exception as exc:
            failed_count += 1
            print(
                f"warning: failed to extract {item}: {exc}; skipped",
                file=sys.stderr,
            )
            continue

        for record in records:
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

    print(
        f"{failed_count} of {len(items)} source files failed extraction "
        "and were skipped",
        file=sys.stderr,
    )

    payload = {
        "version": INDEX_VERSION,
        "dimension": VECTOR_DIMENSION,
        "metric": "cosine",
        "entries": entries,
    }

    if signing_key is None:
        print(
            "warning: index is unsigned; provide --signing-key "
            "to enable Ed25519 signing",
            file=sys.stderr,
        )
        signature = None
    else:
        signature = _sign_payload(payload, signing_key)

    payload["metadata"] = {
        "schema_version": INDEX_VERSION,
        "vector_dimension": VECTOR_DIMENSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signature": signature,
    }
    atomic_write_json(output, payload)

    return len(entries)
