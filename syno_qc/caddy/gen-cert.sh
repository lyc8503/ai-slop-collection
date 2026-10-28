#!/bin/sh
# Generate a self-signed TLS cert/key mimicking the certificate observed on
# Synology QuickConnect relay backends:
#   subject: /C=TW/L=Taipel/O=Synology Inc./CN=synology
#   RSA 2048, 1 years, self-signed.
# Place the resulting cert.pem next to this script (Caddyfile references it).
set -e
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
	-keyout key.pem -out cert.pem \
	-subj '/C=TW/L=Taipel/O=Synology Inc./CN=synology'
chmod 600 key.pem
chmod 644 cert.pem
echo "generated cert.pem + key.pem (CN=synology)"
