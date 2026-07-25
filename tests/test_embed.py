import math

import pytest

from nidana.embed import VECTOR_DIMENSION, vectorize_function
from nidana.matcher import _cosine


def test_vectorize_function_returns_256_finite_floats() -> None:
    record = {
        "name": "demo",
        "addr": 4096,
        "blocks": [
            {
                "addr": 4096,
                "esil_ops": ["push 1", "eax,=", "ret"],
                "outgoing_edges": [],
            }
        ],
    }

    vector = vectorize_function(record)

    assert len(vector) == VECTOR_DIMENSION
    assert all(isinstance(value, float) for value in vector)
    assert all(math.isfinite(value) for value in vector)


def test_vectorize_function_handles_empty_cfg() -> None:
    vector = vectorize_function({"name": "empty", "blocks": []})

    assert len(vector) == VECTOR_DIMENSION
    assert vector == [0.0] * VECTOR_DIMENSION


def test_vectorize_function_handles_malformed_cfg() -> None:
    vector = vectorize_function(
        {
            "blocks": "not-a-list",
            "analysis_incomplete": "yes",
        }
    )

    assert len(vector) == VECTOR_DIMENSION
    assert all(math.isfinite(value) for value in vector)


def test_vectorize_function_ignores_malformed_blocks() -> None:
    vector = vectorize_function(
        {
            "blocks": [
                None,
                {"esil_ops": "not-a-list"},
                {"esil_ops": [1, None]},
            ]
        }
    )

    assert len(vector) == VECTOR_DIMENSION
    assert all(math.isfinite(value) for value in vector)


def test_absolute_hex_addresses_are_normalized() -> None:
    first = {
        "blocks": [
            {
                "esil_ops": [
                    "mov 0x401000, eax",
                    "cmp 0x7fff1234, ebx",
                ],
                "outgoing_edges": [],
            }
        ]
    }
    second = {
        "blocks": [
            {
                "esil_ops": [
                    "mov 0x402000, eax",
                    "cmp 0x7fff5678, ebx",
                ],
                "outgoing_edges": [],
            }
        ]
    }

    first_vector = vectorize_function(first)
    second_vector = vectorize_function(second)

    assert _cosine(first_vector, second_vector) == pytest.approx(1.0)
