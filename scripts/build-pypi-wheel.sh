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

if [[ -z "$binary_path" || -z "$version" || -z "$plat_name" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

root_dir="$(git rev-parse --show-toplevel)"
pkg_dir="$root_dir/pypi"
bin_dir="$pkg_dir/kingfisher/bin"

mkdir -p "$bin_dir" "$out_dir"

binary_name="kingfisher"
if [[ "$binary_path" == *.exe ]]; then
  binary_name="kingfisher.exe"
fi

cp "$binary_path" "$bin_dir/$binary_name"
chmod +x "$bin_dir/$binary_name" || true

cat > "$pkg_dir/kingfisher/_version.py" <<EOF
__version__ = "$version"
EOF

python -m build \
  --wheel \
  --outdir "$out_dir" \
  --config-setting "--plat-name=$plat_name" \
  "$pkg_dir"

echo "Built wheel(s) in $out_dir"
