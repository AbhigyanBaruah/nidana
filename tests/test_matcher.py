import json
import math

import pytest

from nidana.embed import VECTOR_DIMENSION
from nidana.matcher import _cosine, match_vectors


def _vector(index: int, value: float = 1.0) -> list[float]:
    result = [0.0] * VECTOR_DIMENSION
    result[index] = value
    return result


def _write_index(path, *, vector=None, version=1, dimension=256) -> None:
    payload = {
        "version": version,
        "dimension": dimension,
        "metric": "cosine",
        "entries": [
            {
                "cve": "CVE-2025-0001",
                "severity": "high",
                "metadata": {"source": "fixture"},
                "vector": vector or _vector(0),
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cosine_similarity_math() -> None:
    assert _cosine(_vector(0), _vector(0)) == pytest.approx(1.0)
    assert _cosine(_vector(0), _vector(1)) == pytest.approx(0.0)
    assert _cosine([0.0] * VECTOR_DIMENSION, _vector(0)) == 0.0


def test_match_vectors_applies_threshold(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    _write_index(index_path)

    matches = match_vectors(
        [{"name": "hit", "addr": 1, "vector": _vector(0)}],
        index_path,
        threshold=0.9,
    )
    misses = match_vectors(
        [{"name": "miss", "addr": 2, "vector": _vector(1)}],
        index_path,
        threshold=0.9,
    )

    assert matches[0]["cve"] == "CVE-2025-0001"
    assert matches[0]["similarity"] == pytest.approx(1.0)
    assert misses == []


@pytest.mark.parametrize(
    ("field", "value"),
    [("version", 99), ("dimension", 128)],
)
def test_match_vectors_rejects_invalid_index_schema(
    tmp_path,
    field,
    value,
) -> None:
    index_path = tmp_path / f"invalid-{field}.json"
    kwargs = {field: value}
    _write_index(index_path, **kwargs)

    with pytest.raises(ValueError):
        match_vectors([], index_path)


def test_match_vectors_rejects_invalid_input_vector(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    _write_index(index_path)

    with pytest.raises(ValueError):
        match_vectors([{"vector": [math.nan]}], index_path)
