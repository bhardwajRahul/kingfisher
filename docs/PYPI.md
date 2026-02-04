# PyPI Wheel Distribution (Kingfisher CLI)

This document describes how to package the Kingfisher Rust binary into
platform-specific Python wheels so users can install and run `kingfisher` via
`pip` or `uv`.

## Overview

The Python package is a thin wrapper that bundles the compiled Kingfisher binary
inside `kingfisher/bin/` and exposes a `kingfisher` console entry point that
executes it.

Users can run it without installation via `uvx`:

```bash
uvx kingfisher-bin --help
```

## Build prerequisites

1. Build the Kingfisher binary for your target platform (see
   [INSTALLATION.md](INSTALLATION.md) for `make` targets).
2. Install the Python build tooling:

```bash
python -m pip install build
```

## Build a wheel

Run the helper script from the repo root:

```bash
scripts/build-pypi-wheel.sh \
  --binary ./path/to/kingfisher \
  --version 1.2.3 \
  --plat-name manylinux_2_17_x86_64
```

For Windows, pass the `.exe` binary and a Windows platform tag:

```bash
scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_amd64
```

If you only build a Windows x64 binary, you can still ship a `win_arm64` wheel
using the same executable (it runs under emulation on ARM64 Windows):

```bash
scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_arm64
```

The resulting wheel will be placed in `dist-pypi/` by default.

## Test locally

```bash
python -m pip install dist-pypi/kingfisher_bin-*.whl
kingfisher --help
```

## Publish

Upload the wheels to PyPI using `twine` (or your preferred tool):

```bash
python -m pip install twine
python -m twine upload dist-pypi/*
```

### GitHub Actions (recommended)

The repository includes a `pypi-wheels` workflow that:

1. Downloads the release binaries.
2. Builds platform-tagged wheels.
3. Publishes them to PyPI using Trusted Publishing (OIDC).

To use Trusted Publishing, create a PyPI project named `kingfisher-bin` and
enable GitHub Actions as a trusted publisher for this repository and workflow.
No API token is required once Trusted Publishing is configured.

If you do not use Trusted Publishing, generate a PyPI API token and provide it
to `twine` (for example via `TWINE_USERNAME=__token__` and
`TWINE_PASSWORD=<pypi-token>`).
