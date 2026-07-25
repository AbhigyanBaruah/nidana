import json
from base64 import b64encode

from typer.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nidana.cli import ExitCode, app
from nidana.embed import VECTOR_DIMENSION
from nidana.indexer import canonical_payload
from nidana.matcher import IntegrityError


runner = CliRunner()
TEST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _vector(index: int, value: float = 1.0) -> list[float]:
    vector = [0.0] * VECTOR_DIMENSION
    vector[index] = value
    return vector


def _write_index(path, vector=None) -> None:
    payload = {
        "version": 1,
        "dimension": VECTOR_DIMENSION,
        "metric": "cosine",
        "entries": [
            {
                "cve": "CVE-2025-0001",
                "severity": "critical",
                "metadata": {"source": "test"},
                "vector": vector or _vector(0),
            }
        ],
    }
    payload["metadata"] = {
        "schema_version": 1,
        "vector_dimension": VECTOR_DIMENSION,
        "created_at": "2026-01-01T00:00:00+00:00",
        "signature": b64encode(
            TEST_PRIVATE_KEY.sign(canonical_payload(payload))
        ).decode("ascii"),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    public_key_path = path.with_suffix(".pub.pem")
    public_key_path.write_bytes(
        TEST_PRIVATE_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_key_path


def test_help_menu_executes() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert "build-index" in result.stdout
    assert "match" in result.stdout


def test_extract_missing_binary_returns_tool_error() -> None:
    result = runner.invoke(app, ["extract", "missing-binary"])

    assert result.exit_code == ExitCode.TOOL_ERROR


def test_match_missing_database_returns_tool_error(tmp_path) -> None:
    input_file = tmp_path / "vectors.jsonl"
    input_file.write_text(
        json.dumps({"vector": _vector(0)}) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "match",
            str(input_file),
            "--db",
            str(tmp_path / "missing.json"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.TOOL_ERROR


def test_match_without_matches_returns_clean(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    input_file = tmp_path / "vectors.jsonl"
    public_key_path = _write_index(index_path)
    input_file.write_text(
        json.dumps({"name": "clean", "vector": _vector(1)}) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "match",
            str(input_file),
            "--db",
            str(index_path),
            "--format",
            "json",
            "--pubkey",
            str(public_key_path),
        ],
    )

    assert result.exit_code == ExitCode.CLEAN
    assert json.loads(result.stdout) == []


def test_match_with_matches_returns_match_exit_code(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    input_file = tmp_path / "vectors.jsonl"
    public_key_path = _write_index(index_path)
    input_file.write_text(
        json.dumps({"name": "hit", "vector": _vector(0)}) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "match",
            str(input_file),
            "--db",
            str(index_path),
            "--format",
            "json",
            "--pubkey",
            str(public_key_path),
        ],
    )

    assert result.exit_code == ExitCode.MATCHES_FOUND
    assert json.loads(result.stdout)[0]["cve"] == "CVE-2025-0001"


def test_match_output_format_switches(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    input_file = tmp_path / "vectors.jsonl"
    public_key_path = _write_index(index_path)
    input_file.write_text(
        json.dumps({"name": "hit", "vector": _vector(0)}) + "\n",
        encoding="utf-8",
    )

    common_args = [
        "match",
        str(input_file),
        "--db",
        str(index_path),
        "--pubkey",
        str(public_key_path),
    ]

    json_result = runner.invoke(app, [*common_args, "--format", "json"])
    sarif_result = runner.invoke(app, [*common_args, "--format", "sarif"])
    table_result = runner.invoke(app, [*common_args, "--format", "table"])

    assert json.loads(json_result.stdout)[0]["cve"] == "CVE-2025-0001"
    assert json.loads(sarif_result.stdout)["version"] == "2.1.0"
    assert "NIDANA Matches" in table_result.stdout


def test_match_unsigned_index_returns_integrity_failure(tmp_path) -> None:
    index_path = tmp_path / "unsigned.json"
    input_file = tmp_path / "vectors.jsonl"
    index_path.write_text(
        json.dumps(
            {
                "version": 1,
                "dimension": VECTOR_DIMENSION,
                "metric": "cosine",
                "entries": [],
                "metadata": {
                    "schema_version": 1,
                    "vector_dimension": VECTOR_DIMENSION,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "signature": None,
                },
            }
        ),
        encoding="utf-8",
    )
    input_file.write_text(
        json.dumps({"vector": _vector(0)}) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "match",
            str(input_file),
            "--db",
            str(index_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.INTEGRITY_FAILURE


def test_update_integrity_failure_preserves_exit_code(monkeypatch) -> None:
    def fail_update(*_args, **_kwargs):
        raise IntegrityError("signature verification failed")

    monkeypatch.setattr("nidana.cli.update_index", fail_update)

    result = runner.invoke(app, ["update", "--url", "https://example.test"])

    assert result.exit_code == ExitCode.INTEGRITY_FAILURE
