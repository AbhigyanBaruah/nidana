import json

from nidana import indexer


def test_build_index_skips_failed_extraction(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    good_file = tmp_path / "good.bin"
    bad_file = tmp_path / "not-a-binary.txt"
    output = tmp_path / "index.json"
    good_file.write_bytes(b"good")
    bad_file.write_text("source text", encoding="utf-8")

    def fake_extract(path, _r2_path):
        if path == bad_file:
            raise RuntimeError("radare2 rejected input")
        return [
            {
                "name": "good_function",
                "addr": 4096,
                "blocks": [
                    {
                        "esil_ops": ["ret"],
                        "outgoing_edges": [],
                    }
                ],
            }
        ]

    monkeypatch.setattr(indexer, "_extract_records", fake_extract)

    entry_count = indexer.build_index(
        tmp_path,
        "CVE-2025-0001",
        output,
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    captured = capsys.readouterr()

    assert entry_count == 1
    assert len(payload["entries"]) == 1
    assert payload["entries"][0]["metadata"]["source"] == str(good_file)
    assert str(bad_file) in captured.err
    assert "1 of 2 source files failed extraction and were skipped" in captured.err
