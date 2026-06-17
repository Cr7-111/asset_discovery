#!/bin/sh
set -eu

mkdir -p /certs

if [ -f /certs/lab.crt ] && [ -f /certs/lab.key ]; then
  echo "Lab certificates already exist."
  exit 0
fi

openssl req \
  -x509 \
  -nodes \
  -newkey rsa:2048 \
  -days 3650 \
  -keyout /certs/lab.key \
  -out /certs/lab.crt \
  -config /templates/openssl.cnf

chmod 644 /certs/lab.crt
chmod 600 /certs/lab.key

echo "Lab certificates generated."

