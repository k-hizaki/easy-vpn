# Easy VPN

Easy VPN is an OpenVPN-based VPN service that can be easily deployed using Docker containers. All you need to do is acquire a domain, point it to your server, open ports **80**, **443**, and **1194**, and run the Docker containers. Certificate issuance, renewal, and management are handled automatically.

## Components

- **Easy VPN Server**: Main OpenVPN server container
- **Easy VPN API**: REST API for managing and distributing user certificates

## Requirements

- Docker
- Docker Compose
- A registered domain name
- Ports 80 (HTTP), 443 (HTTPS), and 1194 (OpenVPN) open on your firewall

## Setup

### 1. Environment Variables

Instead of storing sensitive credentials directly in the `.env` file, we **recommend** using a secrets management service (e.g., AWS Secrets Manager, HashiCorp Vault) or a KMS solution to securely store and retrieve the following values:

- **ADMIN_USER**: Username for API endpoints that require elevated privileges
- **ADMIN_PASS**: Password for the admin API user
- **MASTER_PASSPHRASE**: Passphrase (if used) for deterministic certificate seed
  - When empty, a random seed is generated and stored at /secret/rand.seed. Backup this file to restore certificates on a new server. When set, a deterministic seed is derived from your passphrase.

Your application can fetch these secrets at startup (e.g., via AWS SDK) and inject them into environment variables or configuration files at runtime.

For non-sensitive settings, edit the `.env` file:

```env
HOSTNAME="vpn.example.com"
CONTACT_EMAIL="admin@example.com"
USE_HTTPS=true
TOKEN_MAX_AGE=86400
```

- **HOSTNAME**: Your server's hostname. Must be a registered domain (Let's Encrypt will verify this).
- **USE_HTTPS**:
  - `true` → Automatically request and renew certificates from Let's Encrypt.
  - `false` → Use plain HTTP (no encryption). **Not secure** outside of local testing environments.
- **CONTACT_EMAIL**: Email address for Let's Encrypt to send important notices.
- **TOKEN_MAX_AGE**: Validity period for download tokens (in seconds).

### 2. Configure `server.conf` Template

Before launching the containers, customize your server configuration by editing the template file at `config/server.conf`. This template supports environment-variable expansion, so you can reference paths like `${OPENVPN_DIR}` directly.

Example `config/server.conf`:

```conf
port 1194
proto tcp
dev tun
ca ${OPENVPN_DIR}/easy-rsa/pki/ca.crt
cert ${OPENVPN_DIR}/easy-rsa/pki/issued/easyvpn.crt
key ${OPENVPN_DIR}/easy-rsa/pki/private/easyvpn.key
dh ${OPENVPN_DIR}/easy-rsa/pki/dh.pem

topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# easy-vpn will automatically parse push directives and apply them to iptables.
# push "route x.x.x.x 255.255.255.255"
# push "route example.com 255.255.255.255"
# push "dhcp-option x.x.x.x"

keepalive 10 120
data-ciphers AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
status ${OPENVPN_DIR}/openvpn-status.log
verb 3
```

When the containers start, `update_server.sh` will use `envsubst` to expand all environment variables in this template, generate the final `server.conf`, then automatically search for every `push "route ..."` line and apply corresponding iptables rules for split-tunnel logging and masquerading.

### 3. Build and Launch Containers

```bash
docker-compose build
docker-compose up -d
```

### 4. User Management

#### a. Obtain Admin JWT Token

Log in as an administrator to retrieve a JWT token:

```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"user":"admin","pass":"password"}' \
     http://localhost/login
```

Save the returned token for subsequent API calls.

#### b. Create User Certificate [Admin Only]

```bash
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer {JWT_TOKEN}" \
     -d '{"emails":["user@example.com"]}' \
     http://localhost/create
```

The response includes a download URL with token for the `.ovpn` profile.

### 5. VPN Connection

Import the downloaded `.ovpn` profile into your OpenVPN client and connect.

## All Api Usage

#### a. Obtain Admin JWT Token

Log in as an administrator to retrieve a JWT token:

```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"user":"admin","pass":"password"}' \
     http://localhost/login
```

Save the returned token for subsequent API calls.

#### b. Create User Certificate [Admin Only]

```bash
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer {JWT_TOKEN}" \
     -d '{"emails":["user@example.com"]}' \
     http://localhost/create
```

The response includes a download URL with token for the `.ovpn` profile.

#### c. Revoke User Certificate [Admin Only]

```bash
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer {JWT_TOKEN}" \
     -d '{"emails":["user@example.com"]}' \
     http://localhost/revoke
```

#### d. Download OVPN Profile

Use the token-protected URL from the create response to download the OVPN file:

```bash
curl -L -o user.ovpn "http://localhost/download?t={TOKEN}"
```

#### e. List Connected VPN Users [Admin Only]

Retrieve a list of currently connected users:

```bash
curl -H "Authorization: Bearer {JWT_TOKEN}" \
     http://localhost/connected-users
```

#### f. List All Valid VPN Users [Admin Only]

Retrieve a list of all users with valid certificates:

```bash
curl -H "Authorization: Bearer {JWT_TOKEN}" \
     http://localhost/valid-users
```

## Docker Configuration

- **easy-vpn**:
  - VPN server container (exposes port 1194/TCP)
- **easy-vpn-api**:
  - API server container (exposes ports 80, 443)

## Folder Structure

```plaintext
.
├── api
│   ├── backend.js
│   ├── Dockerfile
│   └── entrypoint.sh
├── config
│   └── server.conf
├── licenses
│   └── gpl-2.0.txt
├── scripts
│   ├── entrypoint.sh
│   ├── init_server.sh
│   └── update_server.sh
├── docker-compose.yml
├── Dockerfile
├── LICENSE
└── .env
```

## License

### Your code

This project’s original code (API, scripts, Dockerfiles, etc.) is licensed under the [MIT License](LICENSE).

### Third‑party components

- **OpenVPN** — GPL v2 ([licenses/gpl-2.0.txt](licenses/gpl-2.0.txt))
- **Easy‑RSA** — GPL v2 ([licenses/gpl-2.0.txt](licenses/gpl-2.0.txt))

By bundling OpenVPN and Easy‑RSA, you agree to comply with the terms of GPL v2 for those components.
