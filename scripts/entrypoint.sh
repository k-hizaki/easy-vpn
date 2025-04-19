#!/bin/bash
set -e

# Initialize and update the server configuration
${SCRIPTS_DIR}/init_server.sh
${SCRIPTS_DIR}/update_server.sh

# Watch for changes to config dir and trigger update (background)
echo "[INFO] Watching config dir for changes..."
inotifywait -m -q -e close_write,moved_to "${CONFIG_DIR}" --format '%w%f' |
while read -r file; do
  echo "[INFO] Change detected in ${file}, running update..."
  "${SCRIPTS_DIR}/update_server.sh"
done &
echo "[INFO] Starting OpenVPN server..."
exec openvpn --config ${SECRET_DIR}/server.conf --writepid /var/run/openvpn.pid