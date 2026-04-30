#!/usr/bin/env sh
set -e

REPO="yourusername/roguedetect"
INSTALL_DIR="/usr/local/bin"

detect_target() {
    OS=$(uname -s)
    ARCH=$(uname -m)
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64)  echo "roguedetect-linux-x86_64" ;;
                aarch64) echo "roguedetect-linux-arm64" ;;
                *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
            esac ;;
        Darwin)
            case "$ARCH" in
                x86_64)  echo "roguedetect-macos-x86_64" ;;
                arm64)   echo "roguedetect-macos-arm64" ;;
                *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
            esac ;;
        *)
            echo "Unsupported OS: $OS" >&2
            exit 1 ;;
    esac
}

ARTIFACT=$(detect_target)
LATEST=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARTIFACT}"

echo "Installing RogueDetect ${LATEST} (${ARTIFACT})..."
curl -fsSL "$URL" -o /tmp/roguedetect
chmod +x /tmp/roguedetect
sudo mv /tmp/roguedetect "${INSTALL_DIR}/roguedetect"

echo "Installed to ${INSTALL_DIR}/roguedetect"
echo ""
echo "Next steps:"
echo "  1. Copy config.yaml.example to config.yaml and edit it"
echo "  2. Linux: sudo setcap cap_net_raw+ep \$(which roguedetect)"
echo "     macOS/Windows: run as root/admin"
echo "  3. roguedetect --config config.yaml"
