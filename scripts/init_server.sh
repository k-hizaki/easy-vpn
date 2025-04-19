#!/bin/bash
set -euo pipefail

echo "[INFO] Server initialization started."

EASYRSA_DIR="${OPENVPN_DIR}/easy-rsa"

# Copy from sample package of EasyRSA
if [ ! -f "${EASYRSA_DIR}/easyrsa" ]; then
    mkdir -p ${EASYRSA_DIR}
    cp -r /usr/share/easy-rsa/* ${EASYRSA_DIR}
fi

cd ${EASYRSA_DIR}

# Initialize PKI and create certificates if Root CA is missing
if [ ! -f "pki/ca.crt" ]; then
  echo "[INFO] Initializing PKI directory..."
  ./easyrsa init-pki
  echo "[INFO] Building Root CA..."
  ./easyrsa --batch build-ca nopass
  echo "[INFO] Building server certificate..."
  ./easyrsa --batch build-server-full easyvpn nopass
  echo "[INFO] Generating Diffie-Hellman parameters. It takes longer..."
  ./easyrsa gen-dh
  echo "[INFO] Initializing CRL..."
  ./easyrsa gen-crl
  echo "[INFO] Initialization complete."
else
  echo "[INFO] RootCA has already initialized. Skipping."
fi
