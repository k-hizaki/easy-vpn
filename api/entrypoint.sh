#!/bin/bash
set -euo pipefail

CERT_DIR=${LETSENCRYPT_DIR}/${HOSTNAME}
SEED_FILE=${SECRET_DIR}/rand.seed

# MASTER_PASSPHRASE environment variable is undefined
if [ -z "${MASTER_PASSPHRASE:-}" ]; then
  if [ ! -f "${SEED_FILE}" ]; then
    echo "[INFO] Generating rand.seed for this instance..."
    openssl rand -base64 32 \
      | fold -w 32 \
      | head -n 1 > "${SEED_FILE}"
    chmod 600 "${SEED_FILE}"
    echo "[INFO] Random seed generated and saved to ${SEED_FILE}."
  fi
  SEED=$(< "${SEED_FILE}")
else
  echo "[INFO] Deriving deterministic seed from MASTER_PASSPHRASE..."
  SEED=$(
    printf '%s' "${MASTER_PASSPHRASE}" \
      | openssl dgst -sha256 -binary \
      | base64 \
      | fold -w 32 \
      | head -n1
  )
  echo "[INFO] Deterministic seed derived."
fi

# Generate SECRET_KEY from seed
echo "[INFO] Generating SECRET_KEY from seed..."
SECRET_KEY=$(
  printf '%s' "${SEED}" \
    | openssl dgst -sha256 -hex \
    | awk '{print $2}'
)
export SECRET_KEY
echo "[INFO] SECRET_KEY is set."

# Issue initial letsencrypt cert
if "${USE_HTTPS}"; then
  echo "[INFO] Obtaining Let's Encrypt cert for ${HOSTNAME}..."
  if ! certbot certonly \
        --non-interactive \
        --agree-tos \
        --email "${CONTACT_EMAIL}" \
        --standalone \
        -d "${HOSTNAME}"; then
    echo "[ERROR] certbot failed; dumping log" >&2
    cat /var/log/letsencrypt/letsencrypt.log >&2
    exit 1
  fi
fi

# Set automatic old tokens cleanup
cat << EOF > /etc/cron.hourly/cleanup
#!/bin/bash
set -euo pipefail
find "${SECRET_DIR}/ovpns" -maxdepth 1 -type f \
     -mmin +$(( TOKEN_MAX_AGE / 60 )) \
     -print -delete
EOF
chmod 0755 /etc/cron.hourly/cleanup

# Start cron
service cron start

# Main entry point for the Easy VPN API service
exec pm2-runtime start backend.js \
     --name easy-vpn-api \
     --watch "${CERT_DIR}/fullchain.pem" \
     --watch "${CERT_DIR}/privkey.pem"
