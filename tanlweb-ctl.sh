#!/usr/bin/env bash

set -e

if [ $# -lt 2 ]; then
  echo "usage: $0 <ipc socket name> {login-url <username> | revoke-refresh-tokens <username>}" >&2
  exit 1
fi

socket_name=$1
cmd=$2
shift 2

send() {
  result=$(ncat -U "/tmp/tanlweb/$socket_name.sock")
  OK_RE='^ok:\s*(.*)$'
  ERR_RE='^error:\s*(.*)$'
  if [[ $result =~ $OK_RE ]]; then
    if [[ -n "${BASH_REMATCH[1]}" ]]; then
      printf "%s\n" "${BASH_REMATCH[1]}"
    fi
    return 0
  elif [[ $result =~ $ERR_RE ]]; then
    printf "%s\n" "${BASH_REMATCH[1]}" >&2
    return 1
  fi
}

case "$cmd" in
  "login-url")
    if [ $# -ne 1 ]; then
      echo "<username> required" >&2
      exit 1
    fi
    printf "login-url %s" "$1" | send
    exit $?
    ;;
  "revoke-refresh-tokens")
    if [ $# -ne 1 ]; then
      echo "<username> required" >&2
      exit 1
    fi
    printf "revoke-refresh-tokens %s" "$1" | send
    exit $?
    ;;
  *)
    echo "unknown command" >&2
    exit 1
    ;;
esac
