#!/usr/bin/env bash

set -e

if [ $# -lt 2 ]; then
  echo "usage: $0 <ipc socket name> {login-url <user uuid>}" >&2
  exit 1
fi

socket_name=$1
cmd=$2
shift 2

case "$cmd" in
  "login-url")
    if [ $# -ne 1 ]; then
      echo "<user uuid> required" >&2
      exit 1
    fi
    result=$(printf "login-url $1" | ncat -U "/tmp/tanlweb/$socket_name.sock")
    OK_RE='^ok:\s*(.*)$'
    ERR_RE='^error:\s*(.*)$'
    if [[ $result =~ $OK_RE ]]; then
      printf "%s\n" "${BASH_REMATCH[1]}"
    elif [[ $result =~ $ERR_RE ]]; then
      printf "%s\n" "${BASH_REMATCH[1]}" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown command" >&2
    ;;
esac
