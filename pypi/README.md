# Kingfisher (Python wheel)

This package ships the Kingfisher CLI as a platform-specific Python wheel.
The `kingfisher` console script executes the bundled binary for your
OS/architecture.

## Usage

```bash
pip install kingfisher-bin
kingfisher --help
```

## Development

Use the helper script in `scripts/build-pypi-wheel.sh` from the repo root to
build a wheel for a specific target after compiling the Rust binary.
