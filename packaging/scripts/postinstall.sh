#!/bin/sh
set -eu

systemd_reload() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

tmpfiles_create() {
  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/arca-dns.conf >/dev/null 2>&1 || true
  fi
}

systemd_reload
tmpfiles_create

exit 0

