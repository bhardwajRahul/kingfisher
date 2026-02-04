#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build-pypi-wheel.sh \
    --binary /path/to/kingfisher[.exe] \
    --version 1.2.3 \
    --plat-name manylinux_2_17_x86_64 \
    [--out-dir dist-pypi]

Notes:
  - Build the Rust binary for your target platform before running this script.
  - Requires: python -m build (pip install build)
USAGE
}

binary_path=""
version=""
plat_name=""
out_dir="dist-pypi"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary_path="$2"
      shift 2
      ;;
    --version)
      version="$2"
      shift 2
      ;;
    --plat-name)
      plat_name="$2"
      shift 2
      ;;
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

PYTHON="${PYTHON:-}"

if [[ -z "${PYTHON}" ]]; then
  if command -v python >/dev/null 2>&1; then
    PYTHON="python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
  else
    echo "Python not found. Install Python 3 (or set PYTHON=/path/to/python3)." >&2
    exit 1
  fi
fi

# Ensure build module exists
"$PYTHON" -m build --version >/dev/null 2>&1 || {
  echo "Installing Python build backend (build)..." >&2
  "$PYTHON" -m pip install -U build >/dev/null
}


# Resolve binary_path to an absolute, normalized path (works without realpath)
if [[ -z "$binary_path" ]]; then
  echo "Missing --binary" >&2
  exit 1
fi

if [[ "$binary_path" != /* ]]; then
  # interpret relative to the directory where the user invoked the script
  binary_path="$PWD/$binary_path"
fi

# Normalize path and verify it exists
if ! binary_path="$(cd "$(dirname "$binary_path")" && pwd)/$(basename "$binary_path")"; then
  echo "Failed to resolve binary path: $binary_path" >&2
  exit 1
fi

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  echo "Tip: check for typos (e.g. 'kiingfisher' vs 'kingfisher')." >&2
  exit 1
fi


root_dir="$(git rev-parse --show-toplevel)"
cd "$root_dir"

pkg_dir="$root_dir/pypi"
bin_dir="$pkg_dir/kingfisher/bin"

mkdir -p "$bin_dir" "$out_dir"

binary_name="kingfisher"
if [[ "$binary_path" == *.exe ]]; then
  binary_name="kingfisher.exe"
fi

cp "$binary_path" "$bin_dir/$binary_name"
chmod +x "$bin_dir/$binary_name" || true
test -x "$bin_dir/$binary_name" || {
  echo "Binary copy failed: $bin_dir/$binary_name" >&2
  exit 1
}
ls -la "$bin_dir/$binary_name"


cat > "$pkg_dir/kingfisher/_version.py" <<EOF
__version__ = "$version"
EOF

"$PYTHON" -m build \
  --wheel \
  --outdir "$out_dir" \
  "$pkg_dir"

echo "Built wheel(s) in $out_dir"
