#!/bin/bash
set -e

echo "Starting ClamAV for ARM64..."

# Download virus definitions if missing
if [ ! -f /var/lib/clamav/main.cvd ]; then
    echo "Downloading virus definitions (this takes 5-10 minutes)..."
    freshclam --foreground --stdout || true
fi

# Start freshclam daemon (background updater)
echo "Starting freshclam background updater..."
freshclam --daemon

# Start ClamAV daemon in foreground (this keeps container running)
echo "Starting ClamAV daemon on port 3310..."
exec clamd --foreground=yes
