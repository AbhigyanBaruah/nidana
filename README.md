# NIDANA

NIDANA is a cross-architecture firmware n-day hunter. It extracts function
control-flow graphs (CFGs) from binaries with radare2, converts normalized
ESIL operations and CFG statistics into 256-dimensional vectors, and matches
those vectors against signed known-vulnerable function signatures.

The extraction bridge currently starts one persistent external radare2
process per binary using its `-q0` pipe protocol. It does not spawn a new
process per function and does not currently link directly against libr.

## Install and build

Requirements:

- Python 3.9 or newer
- [uv](https://docs.astral.sh/uv/)
- A radare2 installation available as `radare2` on `PATH`
- A C++17 compiler and CMake

On Debian/Ubuntu, install the system tools first:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake radare2
```

Create the environment, build the C++ extension, and install NIDANA in
editable mode:

```bash
uv sync --extra dev
uv run nidana --help
```

The package can also be installed with pip after its build dependencies are
available:

```bash
python -m pip install -e .
```

## Usage

Extract CFGs as JSON Lines:

```bash
nidana extract ./firmware.bin --r2-path radare2 > functions.jsonl
```

Embed extracted functions into 256-dimensional vectors:

```bash
nidana embed functions.jsonl > vectors.jsonl
cat functions.jsonl | nidana embed > vectors.jsonl
```

Build a signed local vulnerability index. The signing key must be an
Ed25519 private key in PEM format:

```bash
nidana build-index \
  --source ./reference-binaries \
  --cve CVE-2025-0001 \
  --signing-key ./keys/index-signing-private.pem \
  --output ./nidana.index.json
```

Unsigned indexes are supported for development but are rejected by matching
and update verification.

Match vectors against an index. Use `--pubkey` for a deployment-specific
Ed25519 public key; otherwise NIDANA uses its pinned key:

```bash
nidana match vectors.jsonl \
  --db ./nidana.index.json \
  --pubkey ./keys/index-signing-public.pem \
  --format table
```

The `embed` and `match` input file arguments are optional; stdin is used when
they are omitted, so stages can be composed:

```bash
nidana extract ./firmware.bin | nidana embed | \
  nidana match --db ./nidana.index.json --format json
```

Run extraction, embedding, and optional matching as one operation:

```bash
nidana scan ./firmware.bin \
  --db ./nidana.index.json \
  --pubkey ./keys/index-signing-public.pem \
  --format sarif
```

Fetch and atomically install a signed index. The URL is configurable for
private deployments; the default points to the project’s placeholder raw
GitHub URL:

```bash
nidana update \
  --url https://example.org/nidana.index.json \
  --output ./nidana.index.json \
  --pubkey ./keys/index-signing-public.pem
```

Exit codes are designed for CI/CD: `0` means no matches, `1` means matches
were found, `2` means a tool or input error, `3` means an index schema
mismatch, and `4` means an integrity or signature failure.

## Current Limitations

- The embedding approach is currently a deterministic feature-hashing
  baseline over normalized ESIL tokens plus structural CFG statistics. It is
  **not a trained neural network**. A learned GNN/embedding model is a future
  direction.
- Aggressive compiler inlining (`-O3`) can fold a vulnerable function into its
  caller. Whole-function matching may not detect the vulnerability in that
  case.
- Matching is currently a brute-force cosine scan, not FAISS-backed. It will
  not scale past a few thousand signatures without a follow-up optimization
  pass.
