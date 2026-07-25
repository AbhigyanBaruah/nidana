import json

from typer.testing import CliRunner

from nidana.cli import ExitCode, app
from nidana.embed import VECTOR_DIMENSION


runner = CliRunner()


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
    path.write_text(json.dumps(payload), encoding="utf-8")


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
    _write_index(index_path)
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
        ],
    )

    assert result.exit_code == ExitCode.CLEAN
    assert json.loads(result.stdout) == []


def test_match_with_matches_returns_match_exit_code(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    input_file = tmp_path / "vectors.jsonl"
    _write_index(index_path)
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
        ],
    )

    assert result.exit_code == ExitCode.MATCHES_FOUND
    assert json.loads(result.stdout)[0]["cve"] == "CVE-2025-0001"


def test_match_output_format_switches(tmp_path) -> None:
    index_path = tmp_path / "index.json"
    input_file = tmp_path / "vectors.jsonl"
    _write_index(index_path)
    input_file.write_text(
        json.dumps({"name": "hit", "vector": _vector(0)}) + "\n",
        encoding="utf-8",
    )

    common_args = [
        "match",
        str(input_file),
        "--db",
        str(index_path),
    ]

    json_result = runner.invoke(app, [*common_args, "--format", "json"])
    sarif_result = runner.invoke(app, [*common_args, "--format", "sarif"])
    table_result = runner.invoke(app, [*common_args, "--format", "table"])

    assert json.loads(json_result.stdout)[0]["cve"] == "CVE-2025-0001"
    assert json.loads(sarif_result.stdout)["version"] == "2.1.0"
    assert "NIDANA Matches" in table_result.stdout
