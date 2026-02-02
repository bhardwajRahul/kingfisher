#!/usr/bin/env bash
# Install Kingfisher as a Husky pre-commit hook
# Usage: ./install-husky.sh [--uninstall]
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install-husky.sh [OPTIONS]

Adds Kingfisher to your Husky pre-commit hook.

Options:
  --uninstall    Remove Kingfisher from the Husky pre-commit hook
  --use-docker   Use Docker instead of local binary (no installation needed)
  --auto-install Auto-download kingfisher binary if not present
  -h, --help     Show this help message

Requirements:
  - Node.js project with Husky already initialized
  - OR run this script after 'npx husky init'

USAGE
}

UNINSTALL=false
USE_DOCKER=false
AUTO_INSTALL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    --use-docker)
      USE_DOCKER=true
      shift
      ;;
    --auto-install)
      AUTO_INSTALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Find Husky directory
find_husky_dir() {
  if [[ -d ".husky" ]]; then
    echo ".husky"
  elif [[ -d ".config/husky" ]]; then
    echo ".config/husky"
  else
    echo ""
  fi
}

HUSKY_DIR="$(find_husky_dir)"

if [[ -z "$HUSKY_DIR" ]]; then
  echo "Error: Husky directory not found." >&2
  echo "Initialize Husky first with: npx husky init" >&2
  exit 1
fi

PRE_COMMIT="$HUSKY_DIR/pre-commit"
MARKER="# kingfisher-scan"

# Determine the scan command
if $USE_DOCKER; then
  SCAN_CMD='docker run --rm -v "$(pwd)":/src ghcr.io/mongodb/kingfisher:latest scan /src --staged --quiet --no-update-check'
elif $AUTO_INSTALL; then
  # Use the auto-download script approach
  SCAN_CMD='curl -fsSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/kingfisher-pre-commit-auto.sh | bash'
else
  SCAN_CMD='kingfisher scan . --staged --quiet --no-update-check'
fi

uninstall() {
  if [[ -f "$PRE_COMMIT" ]]; then
    # Remove kingfisher lines from pre-commit
    if grep -q "$MARKER" "$PRE_COMMIT"; then
      # Create temp file without kingfisher lines
      local tmpfile
      tmpfile="$(mktemp)"
      grep -v "$MARKER" "$PRE_COMMIT" | grep -v "kingfisher scan\|kingfisher:latest\|kingfisher-pre-commit-auto" > "$tmpfile" || true
      mv "$tmpfile" "$PRE_COMMIT"
      chmod +x "$PRE_COMMIT"
      echo "Kingfisher removed from $PRE_COMMIT"
    else
      echo "Kingfisher not found in $PRE_COMMIT"
    fi
  else
    echo "No pre-commit hook found at $PRE_COMMIT"
  fi
}

install() {
  # Create pre-commit if it doesn't exist
  if [[ ! -f "$PRE_COMMIT" ]]; then
    cat > "$PRE_COMMIT" <<'EOF'
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

EOF
    chmod +x "$PRE_COMMIT"
    echo "Created $PRE_COMMIT"
  fi

  # Check if kingfisher is already installed
  if grep -q "$MARKER" "$PRE_COMMIT" 2>/dev/null; then
    echo "Kingfisher is already configured in $PRE_COMMIT"
    return 0
  fi

  # Append kingfisher scan command
  cat >> "$PRE_COMMIT" <<EOF

$MARKER
$SCAN_CMD
EOF

  echo "Kingfisher added to $PRE_COMMIT"

  if ! $USE_DOCKER && ! $AUTO_INSTALL; then
    if ! command -v kingfisher >/dev/null 2>&1; then
      echo ""
      echo "Note: kingfisher is not installed. Install it with:"
      echo "  curl -fsSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash"
      echo ""
      echo "Or re-run this script with --use-docker or --auto-install"
    fi
  fi
}

if $UNINSTALL; then
  uninstall
else
  install
fi
