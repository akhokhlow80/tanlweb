#!/bin/sh

set -e

v() {
  >&2 echo '[#]' $@
  $@
}

v go build .
v go test ./...
v install tanlweb /usr/bin/
v install tanlweb-ctl.sh /usr/bin/tanlweb-ctl
v install tanlweb@.service /etc/systemd/system
echo 'Run ./gen-conf.sh to generate config'
echo 'Run to enable: systemctl enable --now tanlweb@<profile>.service'
