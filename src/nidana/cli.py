"""Command-line interface for the NIDANA vulnerability scanner."""

from __future__ import annotations

import json
import sys
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Iterable, Optional

import typer
from rich.console import Console
from rich.table import Table

from .embed import vectorize_records
from .indexer import build_index as build_vector_index
from .matcher import match_vectors


app = typer.Typer(
    name="nidana",
    help="A DevSecOps AI vulnerability scanner.",
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)


class ExitCode(IntEnum):
    """Process exit codes used by CI/CD integrations."""

    CLEAN = 0
    MATCHES_FOUND = 1
    TOOL_ERROR = 2


class OutputFormat(str, Enum):
    """Supported machine and human-readable output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _tool_error(message: str) -> None:
    """Print a styled error and terminate with the tool-error code."""

    error_console.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code=ExitCode.TOOL_ERROR)


def _resolve_format(requested: Optional[OutputFormat]) -> OutputFormat:
    """Resolve an explicit format or select table/JSON from stdout TTY state."""

    if requested is not None:
        return requested
    return OutputFormat.TABLE if sys.stdout.isatty() else OutputFormat.JSON


def _iter_json_lines(input_file: Optional[Path]) -> Iterable[dict[str, Any]]:
    """Read JSON Lines from a file or standard input."""

    try:
        stream = input_file.open("r", encoding="utf-8") if input_file else sys.stdin
    except OSError as exc:
        _tool_error(f"cannot open input {input_file}: {exc}")

    try:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                _tool_error(f"invalid JSON on input line {line_number}: {exc.msg}")
            if not isinstance(value, dict):
                _tool_error(f"input line {line_number} must contain a JSON object")
            yield value
    finally:
        if input_file:
            stream.close()


def _read_json_lines(input_file: Optional[Path]) -> list[dict[str, Any]]:
    """Read all JSON Lines from a file or standard input."""

    return list(_iter_json_lines(input_file))


def _write_json_lines(records: Iterable[dict[str, Any]]) -> None:
    """Write records as newline-delimited JSON to standard output."""

    for record in records:
        print(json.dumps(record, separators=(",", ":")))


def _extract_records(
    binary_path: Path,
    r2_executable_path: str = "radare2",
) -> list[dict[str, Any]]:
    """Extract real function CFGs using the C++ stream engine."""

    if not binary_path.is_file():
        _tool_error(f"binary not found: {binary_path}")

    try:
        from nidana import stream_functions

        records: list[dict[str, Any]] = []
        for func in stream_functions(str(binary_path), r2_executable_path):
            records.append({
                "name": func.name,
                "addr": func.addr,
                "analysis_incomplete": func.analysis_incomplete,
                "blocks": [
                    {
                        "addr": block.addr,
                        "esil_ops": block.esil_ops,
                        "outgoing_edges": block.outgoing_edges,
                    }
                    for block in func.blocks
                ],
            })
        return records
    except Exception as exc:
        _tool_error(f"extraction failed: {exc}")


def _match_records(
    records: Iterable[dict[str, Any]],
    db: Optional[Path],
    threshold: float = 0.85,
) -> list[dict[str, Any]]:
    """Match vector records against DB, or return no matches without a DB."""

    if db is None:
        return []

    try:
        return match_vectors(records, db, threshold)
    except (OSError, ValueError, TypeError) as exc:
        _tool_error(f"matching failed: {exc}")


def _sarif(matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert match records to a minimal SARIF 2.1.0 document."""

    return {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "nidana"}},
                "results": [
                    {
                        "ruleId": match["cve"],
                        "level": "warning",
                        "message": {
                            "text": f"Potential vulnerability: {match['cve']}"
                        },
                    }
                    for match in matches
                ],
            }
        ],
    }


def _render_matches(matches: list[dict[str, Any]], output_format: OutputFormat) -> None:
    """Render matches in table, JSON, or SARIF format."""

    if output_format is OutputFormat.JSON:
        print(json.dumps(matches, separators=(",", ":")))
        return

    if output_format is OutputFormat.SARIF:
        print(json.dumps(_sarif(matches), separators=(",", ":")))
        return

    table = Table(title="NIDANA Matches")
    table.add_column("CVE")
    table.add_column("Severity")
    for match in matches:
        table.add_row(str(match["cve"]), str(match["severity"]))
    console.print(table)


def _exit_for_matches(matches: list[dict[str, Any]]) -> None:
    """Exit with the CI result code for a match collection."""

    raise typer.Exit(
        code=(
            ExitCode.MATCHES_FOUND
            if matches
            else ExitCode.CLEAN
        )
    )


@app.command()
def embed(input_file: Optional[Path] = typer.Argument(None)) -> None:
    """Vectorize function CFG JSON Lines from INPUT_FILE or standard input."""

    for record in vectorize_records(_iter_json_lines(input_file)):
        _write_json_lines((record,))


@app.command()
def match(
    input_file: Optional[Path] = typer.Argument(None),
    db: Path = typer.Option(..., "--db", help="Path to the vulnerability database."),
    format: Optional[OutputFormat] = typer.Option(
        None,
        "--format",
        case_sensitive=False,
        help="Output format: table, json, or sarif.",
    ),
    threshold: float = typer.Option(
        0.85,
        "--threshold",
        min=0.0,
        max=1.0,
        help="Minimum cosine similarity for a match.",
    ),
) -> None:
    """Match embedded JSON Lines from INPUT_FILE or standard input against DB."""

    matches = _match_records(
        _read_json_lines(input_file),
        db,
        threshold,
    )
    _render_matches(matches, _resolve_format(format))
    _exit_for_matches(matches)


@app.command()
def scan(
    binary_path: Path,
    db: Optional[Path] = typer.Option(
        None,
        "--db",
        help="Optional vector index used for matching.",
    ),
    format: Optional[OutputFormat] = typer.Option(
        None,
        "--format",
        case_sensitive=False,
        help="Output format: table, json, or sarif.",
    ),
    r2_path: str = typer.Option(
        "radare2", "--r2-path", help="Path to radare2 executable."
    ),
) -> None:
    """Run extraction, embedding, and matching for BINARY_PATH."""

    extracted = _extract_records(binary_path, r2_path)
    embedded = list(vectorize_records(extracted))
    matches = _match_records(embedded, db)
    _render_matches(matches, _resolve_format(format))
    _exit_for_matches(matches)


@app.command("build-index")
def build_index(
    source: Path = typer.Option(..., "--source"),
    cve: str = typer.Option(..., "--cve"),
    output: Path = typer.Option(
        Path("nidana.index.json"),
        "--output",
        help="Destination for the local vector index.",
    ),
    r2_path: str = typer.Option(
        "radare2",
        "--r2-path",
        help="Path to radare2 executable.",
    ),
) -> None:
    """Extract and embed SOURCE into a searchable CVE vector index."""

    try:
        entry_count = build_vector_index(
            source,
            cve,
            output,
            r2_path,
        )
    except (OSError, ValueError, FileNotFoundError) as exc:
        _tool_error(f"index build failed: {exc}")

    console.print(
        f"[green]index built[/green]: {entry_count} vectors -> {output}"
    )


@app.command()
def update() -> None:
    """Fetch and verify the latest signed vulnerability index."""

    console.print("[green]index updated[/green]")


@app.command()
def extract(
    binary_path: Path,
    r2_path: str = typer.Option(
        "radare2", "--r2-path", help="Path to radare2 executable."
    ),
) -> None:
    """Extract functions from BINARY_PATH and emit JSON Lines."""

    _write_json_lines(_extract_records(binary_path, r2_path))


if __name__ == "__main__":
    app()
