#!/usr/bin/env bash

set -e

v() {
  >&2 echo '[#]' $@
  $@
}

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <profile name> <host> <admin port> <peerconfs port>" >&2
  exit 1
fi

profile="$1"
host="$2"
admin_port="$3"
peerconfs_port="$4"

config_dir="/etc/tanlweb/$profile"
data_dir="/var/lib/tanlweb/$profile"

v mkdir -p "$config_dir"
v chmod 600 "$config_dir"
v mkdir -p "$data_dir"
v chmod 600 "$data_dir"

v cat > "$config_dir/config" << EOF
# Admin
ADMIN_HTTP_BIND=:$admin_port
AUTH_PRIV_KEY=$(head -c128 /dev/random | base64 --wrap 0)
ADMIN_BASE_URI=https://$host:$admin_port
# 3 h
LOGIN_TOKEN_LIFETIME_SECS=10800
# 1 w
REFRESH_TOKEN_LIFETIME_SECS=604800
# 3 m
ACCESS_TOKEN_LIFETIME_SECS=180
# 1 w
REQ_KEY_ROTATION_INTERVAL_SECS=604800
PEER_CONFS_BASE_URI=https://$host:$peerconfs_port
IPC_SOCKET_NAME=$profile
ADMIN_TLS_KEY_PATH=$config_dir/server.key
ADMIN_TLS_CERT_PATH=$config_dir/server.cert

# Peerconfs
PEER_CONFS_HTTP_BIND=:$peerconfs_port
PEER_CONFS_TLS_KEY_PATH=$config_dir/server.key
PEER_CONFS_TLS_CERT_PATH=$config_dir/server.cert

# Common
DEBUG_MODE=false
DB_PATH=$data_dir/db
EOF

echo "Config written to $config_dir/config" >&2
