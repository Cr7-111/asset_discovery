#!/bin/sh
set -eu

while [ ! -f /etc/nginx/certs/lab.crt ] || [ ! -f /etc/nginx/certs/lab.key ]; do
  echo "Waiting for TLS certificate files..."
  sleep 1
done

exec nginx -g 'daemon off;'

