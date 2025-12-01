#!/usr/bin/env bash
set -e

# Minimal installer for iio-dsu-bridge (user service, SteamOS-friendly)
# 1) Downloads the binary
# 2) Creates a systemd --user service
# 3) Enables and starts it
#
# Edit BIN_URL to match your Release asset URL.
# Example for "latest":
#   https://github.com/Sebalvarez97/iio-dsu-bridge/releases/latest/download/iio-dsu-bridge

SERVICE_NAME="iio-dsu-bridge"
BIN_DIR="$HOME/.local/bin"
BIN_PATH="$BIN_DIR/iio-dsu-bridge"
SERVICE_FILE="$HOME/.config/systemd/user/${SERVICE_NAME}.service"

# Hosted release asset for this fork
BIN_URL="https://github.com/rottiakash/iio-dsu-bridge/releases/latest/download/iio-dsu-bridge"

echo "==> Creating required folders..."
mkdir -p "$BIN_DIR"
mkdir -p "$(dirname "$SERVICE_FILE")"

echo "==> Downloading binary from: $BIN_URL"
if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi
curl -fL "$BIN_URL" -o "$BIN_PATH"
chmod +x "$BIN_PATH"

echo "==> Writing user service: $SERVICE_FILE"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=IIO -> DSU Bridge (ROG Ally)
After=network.target

[Service]
ExecStart=$BIN_PATH -rate=250 -addr=127.0.0.1:26760
Restart=on-failure

[Install]
WantedBy=default.target
EOF

echo "==> Reloading systemd user daemon and enabling service..."
systemctl --user daemon-reload
systemctl --user enable --now "${SERVICE_NAME}.service" || {
  echo "Hint: If systemd --user isn't active in this shell, try re-login or run:"
  echo "      systemctl --user daemon-reload && systemctl --user enable --now ${SERVICE_NAME}.service"
  exit 1
}

echo "==> Done. Follow logs with:"
echo "journalctl --user -u ${SERVICE_NAME} -f"
