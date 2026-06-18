#!/bin/bash
# ============================================================================
# setup_tls.sh - Generate self-signed ECDSA CA + Server Certificate
# For educational use only (Lab 4 - TLS Deployment Task)
# ============================================================================

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

echo "=== Step 1: Generate ECDSA CA Key ==="
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca_key.pem"

echo "=== Step 2: Create Self-Signed CA Certificate ==="
openssl req -new -x509 -key "$CERT_DIR/ca_key.pem" \
    -out "$CERT_DIR/ca_cert.pem" -days 3650 \
    -subj "/C=VN/ST=HCM/O=Lab4-CA/CN=Lab4 Root CA" \
    -sha256

echo "=== Step 3: Generate Server ECDSA Key ==="
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server_key.pem"

echo "=== Step 4: Create Server CSR ==="
openssl req -new -key "$CERT_DIR/server_key.pem" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=VN/ST=HCM/O=Lab4-Server/CN=localhost"

echo "=== Step 5: Create Extensions File ==="
cat > "$CERT_DIR/server_ext.cnf" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
DNS.2=*.localhost
IP.1=127.0.0.1
EOF

echo "=== Step 6: Sign Server Certificate with CA ==="
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca_cert.pem" -CAkey "$CERT_DIR/ca_key.pem" \
    -CAcreateserial -out "$CERT_DIR/server_cert.pem" \
    -days 365 -sha256 \
    -extfile "$CERT_DIR/server_ext.cnf"

echo "=== Step 7: Verify Certificate Chain ==="
openssl verify -CAfile "$CERT_DIR/ca_cert.pem" "$CERT_DIR/server_cert.pem"

echo ""
echo "=== Generated Files ==="
echo "  CA Key:          $CERT_DIR/ca_key.pem"
echo "  CA Certificate:  $CERT_DIR/ca_cert.pem"
echo "  Server Key:      $CERT_DIR/server_key.pem"
echo "  Server Cert:     $CERT_DIR/server_cert.pem"
echo ""
echo "=== Inspect Server Certificate ==="
openssl x509 -in "$CERT_DIR/server_cert.pem" -text -noout | head -30

echo ""
echo "=== Done! ==="
echo "Use these files with Nginx (nginx_ecdsa.conf) or Apache (apache_ecdsa.conf)"
