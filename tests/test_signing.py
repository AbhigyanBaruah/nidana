import json
from base64 import b64encode

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nidana import indexer, updater
from nidana.embed import VECTOR_DIMENSION
from nidana.indexer import canonical_payload
from nidana.matcher import IntegrityError, _load_index


PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _write_private_key(path) -> None:
    path.write_bytes(
        PRIVATE_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _write_public_key(path) -> None:
    path.write_bytes(
        PRIVATE_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _signed_payload() -> dict:
    payload = {
        "version": 1,
        "dimension": VECTOR_DIMENSION,
        "metric": "cosine",
        "entries": [],
    }
    payload["metadata"] = {
        "schema_version": 1,
        "vector_dimension": VECTOR_DIMENSION,
        "created_at": "2026-01-01T00:00:00+00:00",
        "signature": b64encode(
            PRIVATE_KEY.sign(canonical_payload(payload))
        ).decode("ascii"),
    }
    return payload


def test_build_index_signs_payload(tmp_path, monkeypatch) -> None:
    source = tmp_path / "firmware.bin"
    output = tmp_path / "index.json"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    source.write_bytes(b"fixture")
    _write_private_key(private_key)
    _write_public_key(public_key)

    monkeypatch.setattr(
        indexer,
        "_extract_records",
        lambda *_: [
            {
                "name": "main",
                "addr": 4096,
                "blocks": [
                    {
                        "esil_ops": ["ret"],
                        "outgoing_edges": [],
                    }
                ],
            }
        ],
    )

    assert indexer.build_index(
        source,
        "CVE-2025-0001",
        output,
        signing_key=private_key,
    ) == 1

    entries = _load_index(output, public_key)
    metadata = json.loads(output.read_text())['metadata']

    assert len(entries) == 1
    assert metadata["signature"]


def test_unsigned_index_is_marked_and_rejected(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    source = tmp_path / "firmware.bin"
    output = tmp_path / "index.json"
    public_key = tmp_path / "public.pem"
    source.write_bytes(b"fixture")
    _write_public_key(public_key)

    monkeypatch.setattr(indexer, "_extract_records", lambda *_: [])
    indexer.build_index(source, "CVE-2025-0001", output)

    metadata = json.loads(output.read_text())['metadata']
    captured = capsys.readouterr()

    assert metadata["signature"] is None
    assert "index is unsigned" in captured.err
    with pytest.raises(IntegrityError):
        _load_index(output, public_key)


class _Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _size: int) -> bytes:
        body, self.body = self.body, b""
        return body


def test_update_verifies_before_replacing_local_index(
    tmp_path,
    monkeypatch,
) -> None:
    output = tmp_path / "local-index.json"
    public_key = tmp_path / "public.pem"
    _write_public_key(public_key)
    output.write_text("trusted-local-index", encoding="utf-8")
    payload = _signed_payload()
    body = json.dumps(payload).encode("utf-8")

    monkeypatch.setattr(
        updater,
        "urlopen",
        lambda *_args, **_kwargs: _Response(body),
    )

    assert updater.update_index("https://example.test/index.json", output, public_key) == 0
    assert json.loads(output.read_text()) == payload

    original = output.read_text()
    invalid = dict(payload)
    invalid["entries"] = [{"tampered": True}]
    invalid_body = json.dumps(invalid).encode("utf-8")
    monkeypatch.setattr(
        updater,
        "urlopen",
        lambda *_args, **_kwargs: _Response(invalid_body),
    )

    with pytest.raises(IntegrityError):
        updater.update_index("https://example.test/index.json", output, public_key)

    assert output.read_text() == original
