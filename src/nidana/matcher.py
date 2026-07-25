"""Cosine-similarity matching against a NIDANA vector index."""

from __future__ import annotations

import json
import math
from base64 import b64decode
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .embed import VECTOR_DIMENSION
from .indexer import INDEX_VERSION, canonical_payload


# Deployment-pinned Ed25519 public key. Operators may override it with the
# CLI --pubkey option for private deployments.
NIDANA_PUBKEY = b64decode(
    "3iXm6SY2jAzki+F0YbAfYuJ8Yk3urdY2Qs+P4cRKjv0="
)


class IntegrityError(ValueError):
    """Raised when an index is unsigned, tampered with, or unverifiable."""


class SchemaMismatchError(ValueError):
    """Raised when a verified index has an unsupported schema."""


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


def _public_key(pubkey: Path | bytes | None) -> Ed25519PublicKey:
    """Load a deployment-pinned or explicitly supplied public key."""

    if pubkey is None:
        key_bytes = NIDANA_PUBKEY
    elif isinstance(pubkey, Path):
        try:
            key_data = pubkey.read_bytes()
        except OSError as exc:
            raise IntegrityError(
                f"cannot read public key {pubkey}: {exc}"
            ) from exc
        try:
            key = serialization.load_pem_public_key(key_data)
        except (ValueError, TypeError) as exc:
            raise IntegrityError(
                f"cannot load public key {pubkey}: {exc}"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise IntegrityError("public key is not an Ed25519 key")
        return key
    else:
        key_bytes = pubkey

    if len(key_bytes) != 32:
        raise IntegrityError("Ed25519 public key must be 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:
        raise IntegrityError("invalid Ed25519 public key") from exc


def _load_index(
    db: Path,
    pubkey: Path | bytes | None = None,
) -> list[dict[str, Any]]:
    """Verify an index before validating or returning any indexed fields."""

    try:
        with db.open("r", encoding="utf-8") as index_file:
            payload = json.load(index_file)
    except OSError as exc:
        raise OSError(f"cannot read index {db}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IntegrityError(
            f"cannot verify index {db}: invalid JSON: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise IntegrityError("index root must be a JSON object")

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise IntegrityError("index is unsigned or missing metadata")
    signature = metadata.get("signature")
    if not isinstance(signature, str) or not signature:
        raise IntegrityError("index is unsigned or missing a signature")

    try:
        signature_bytes = b64decode(signature, validate=True)
        _public_key(pubkey).verify(
            signature_bytes,
            canonical_payload(payload),
        )
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise IntegrityError(
            f"index signature verification failed: {exc}"
        ) from exc

    if metadata.get("schema_version") != INDEX_VERSION:
        raise SchemaMismatchError(
            "unsupported index metadata schema version"
        )
    if metadata.get("vector_dimension") != VECTOR_DIMENSION:
        raise SchemaMismatchError(
            "index metadata dimension does not match the embedder"
        )

    if payload.get("version") != INDEX_VERSION:
        raise SchemaMismatchError("unsupported index version")
    if payload.get("dimension") != VECTOR_DIMENSION:
        raise SchemaMismatchError(
            "index dimension does not match the embedder"
        )
    if payload.get("metric") != "cosine":
        raise SchemaMismatchError("unsupported index metric")
    if not isinstance(payload.get("entries"), list):
        raise SchemaMismatchError("index entries must be a JSON array")

    entries: list[dict[str, Any]] = []
    for entry in payload["entries"]:
        if not isinstance(entry, dict):
            raise SchemaMismatchError("index entry must be a JSON object")
        try:
            _validated_vector(entry.get("vector"))
        except ValueError as exc:
            raise SchemaMismatchError(
                f"invalid vector in index entry: {exc}"
            ) from exc
        if not isinstance(entry.get("cve"), str):
            raise SchemaMismatchError(
                "index entry is missing a CVE label"
            )
        entries.append(entry)
    return entries


def match_vectors(
    records: Iterable[dict[str, Any]],
    db: Path,
    threshold: float = 0.85,
    pubkey: Path | bytes | None = None,
) -> list[dict[str, Any]]:
    """Return high-confidence matches for input vector records."""

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")

    entries = _load_index(db, pubkey)
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
