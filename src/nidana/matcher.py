"""Cosine-similarity matching against a NIDANA vector index."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable

from .embed import VECTOR_DIMENSION
from .indexer import INDEX_VERSION


def _validated_vector(value: Any) -> list[float]:
    """Validate and normalize a vector from JSON input."""

    if not isinstance(value, list) or len(value) != VECTOR_DIMENSION:
        raise ValueError(
            f"vector must contain exactly {VECTOR_DIMENSION} values"
        )

    vector = [float(component) for component in value]
    if not all(math.isfinite(component) for component in vector):
        raise ValueError("vector contains a non-finite value")
    return vector


def _cosine(left: list[float], right: list[float]) -> float:
    """Compute cosine similarity for two validated vectors."""

    left_norm = math.sqrt(sum(component * component for component in left))
    right_norm = math.sqrt(sum(component * component for component in right))
    if not left_norm or not right_norm:
        return 0.0

    return sum(a * b for a, b in zip(left, right)) / (
        left_norm * right_norm
    )


def _load_index(db: Path) -> list[dict[str, Any]]:
    """Load and validate an index file."""

    try:
        with db.open("r", encoding="utf-8") as index_file:
            payload = json.load(index_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read index {db}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("index root must be a JSON object")
    if payload.get("version") != INDEX_VERSION:
        raise ValueError("unsupported index version")
    if payload.get("dimension") != VECTOR_DIMENSION:
        raise ValueError("index dimension does not match the embedder")
    if payload.get("metric") != "cosine":
        raise ValueError("unsupported index metric")
    if not isinstance(payload.get("entries"), list):
        raise ValueError("index entries must be a JSON array")

    entries: list[dict[str, Any]] = []
    for entry in payload["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("index entry must be a JSON object")
        _validated_vector(entry.get("vector"))
        if not isinstance(entry.get("cve"), str):
            raise ValueError("index entry is missing a CVE label")
        entries.append(entry)
    return entries


def match_vectors(
    records: Iterable[dict[str, Any]],
    db: Path,
    threshold: float = 0.85,
) -> list[dict[str, Any]]:
    """Return high-confidence matches for input vector records."""

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")

    entries = _load_index(db)
    matches: list[dict[str, Any]] = []

    for record in records:
        vector = _validated_vector(record.get("vector"))
        best_by_cve: dict[str, dict[str, Any]] = {}

        for entry in entries:
            similarity = _cosine(vector, _validated_vector(entry["vector"]))
            if similarity < threshold:
                continue

            candidate = {
                "cve": entry["cve"],
                "severity": entry.get("severity", "unknown"),
                "similarity": round(similarity, 6),
                "metadata": entry.get("metadata", {}),
                "function": {
                    "name": record.get("name"),
                    "addr": record.get("addr"),
                },
            }
            previous = best_by_cve.get(entry["cve"])
            if previous is None or candidate["similarity"] > previous["similarity"]:
                best_by_cve[entry["cve"]] = candidate

        matches.extend(best_by_cve.values())

    return matches
