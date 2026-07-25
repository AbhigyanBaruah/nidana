"""Deterministic feature extraction and vectorization for function CFGs."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from typing import Any


VECTOR_DIMENSION = 256
_STRUCTURAL_DIMENSIONS = 16
_TOKEN_PATTERN = re.compile(
    r"0x[0-9a-fA-F]+|[A-Za-z_][\w.]*|-?\d+|[^\s]+"
)


def _tokenize(operation: str) -> list[str]:
    """Tokenize one ESIL operation into stable lexical features."""

    return _TOKEN_PATTERN.findall(operation.lower())


def _token_index(token: str) -> tuple[int, float]:
    """Map a token to a feature bucket and a deterministic sign."""

    digest = hashlib.blake2b(
        token.encode("utf-8"),
        digest_size=8,
        person=b"nidana-v1",
    ).digest()
    value = int.from_bytes(digest, byteorder="little", signed=False)
    bucket_count = VECTOR_DIMENSION - _STRUCTURAL_DIMENSIONS
    index = _STRUCTURAL_DIMENSIONS + (value % bucket_count)
    sign = 1.0 if value & 1 else -1.0
    return index, sign


def _as_operations(record: Mapping[str, Any]) -> list[str]:
    """Aggregate ESIL operations from every basic block in a record."""

    operations: list[str] = []
    blocks = record.get("blocks", [])
    if not isinstance(blocks, list):
        return operations

    for block in blocks:
        if not isinstance(block, Mapping):
            continue
        esil_ops = block.get("esil_ops", [])
        if not isinstance(esil_ops, list):
            continue
        operations.extend(
            operation
            for operation in esil_ops
            if isinstance(operation, str)
        )
    return operations


def vectorize_function(record: Mapping[str, Any]) -> list[float]:
    """Create a normalized, fixed-size vector for one function CFG."""

    vector = [0.0] * VECTOR_DIMENSION
    blocks = record.get("blocks", [])
    valid_blocks = [
        block for block in blocks
        if isinstance(block, Mapping)
    ] if isinstance(blocks, list) else []
    operations = _as_operations(record)

    edges = 0
    max_block_ops = 0
    for block in valid_blocks:
        outgoing = block.get("outgoing_edges", [])
        if isinstance(outgoing, list):
            edges += len(outgoing)
        esil_ops = block.get("esil_ops", [])
        if isinstance(esil_ops, list):
            max_block_ops = max(max_block_ops, len(esil_ops))

    token_count = 0
    unique_tokens: set[str] = set()
    for operation in operations:
        for token in _tokenize(operation):
            index, sign = _token_index(token)
            vector[index] += sign
            token_count += 1
            unique_tokens.add(token)

    block_count = len(valid_blocks)
    operation_count = len(operations)
    vector[0] = math.log1p(block_count)
    vector[1] = math.log1p(operation_count)
    vector[2] = math.log1p(edges)
    vector[3] = math.log1p(max_block_ops)
    vector[4] = edges / block_count if block_count else 0.0
    vector[5] = operation_count / block_count if block_count else 0.0
    vector[6] = math.log1p(token_count)
    vector[7] = math.log1p(len(unique_tokens))
    vector[8] = 1.0 if record.get("analysis_incomplete", False) else 0.0

    norm = math.sqrt(sum(value * value for value in vector))
    if norm:
        vector = [value / norm for value in vector]

    return vector


def vectorize_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the original function record with a 256-float vector added."""

    result = dict(record)
    result["vector"] = vectorize_function(record)
    return result


def vectorize_records(
    records: Iterable[Mapping[str, Any]],
) -> Iterator[dict[str, Any]]:
    """Vectorize records lazily so JSONL pipelines remain streamable."""

    for record in records:
        yield vectorize_record(record)
