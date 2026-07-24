#!/usr/bin/env bash
#
# solana-tx-guard installer
#
# Installs the skill into a Claude Code / Codex agent config by copying the
# skill/ folder into <target>/.claude/skills/solana-tx-guard/. Transparent and
# dependency-free: it only copies files and prints what it did. No binaries are
# downloaded or executed.
#
# Usage:
#   ./install.sh                 # install into ./.claude/skills (current project)
#   ./install.sh --global        # install into ~/.claude/skills
#   ./install.sh --dir <path>    # install into <path>/.claude/skills
#   curl -fsSL <raw-url>/install.sh | bash            # project install
#   curl -fsSL <raw-url>/install.sh | bash -s -- --global
#
set -euo pipefail

REPO="Anon1one/solana-tx-guard"
SKILL_NAME="solana-tx-guard"
BRANCH="main"

TARGET_BASE="."
for arg in "$@"; do
  case "$arg" in
    --global) TARGET_BASE="$HOME" ;;
    --dir) shift_next=1 ;;
    *) if [ "${shift_next:-0}" = "1" ]; then TARGET_BASE="$arg"; shift_next=0; fi ;;
  esac
done

DEST="$TARGET_BASE/.claude/skills/$SKILL_NAME"
echo "→ Installing $SKILL_NAME into: $DEST"

# Locate the source skill/ folder: either we're running from a clone, or we
# fetch the repo tarball when piped via curl.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"

copy_from_local() {
  mkdir -p "$DEST"
  cp -R "$1/skill/." "$DEST/"
  # ship the command alongside the skill for agents that read commands/
  if [ -d "$1/commands" ]; then
    mkdir -p "$TARGET_BASE/.claude/commands"
    cp "$1/commands/"*.md "$TARGET_BASE/.claude/commands/" 2>/dev/null || true
  fi
}

if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/skill" ]; then
  copy_from_local "$SCRIPT_DIR"
else
  echo "→ Fetching $REPO@$BRANCH ..."
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" -o "$TMP/s.tgz"
  else
    wget -qO "$TMP/s.tgz" "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH"
  fi
  tar -xzf "$TMP/s.tgz" -C "$TMP"
  SRC="$(find "$TMP" -maxdepth 1 -type d -name "${SKILL_NAME}-*" | head -1)"
  copy_from_local "$SRC"
fi

echo "✓ Installed skill files:"
ls -1 "$DEST" | sed 's/^/    /'
echo ""
echo "Next:"
echo "  • The agent will route to skill/SKILL.md automatically."
echo "  • For the library/CLI:  npm install solana-tx-guard"
echo "  • Try:  txguard check --tx <base64> --owner <pubkey> --max-sol 0.5"
echo ""
echo "Done."
