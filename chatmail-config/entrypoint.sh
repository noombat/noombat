#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Entrypoint for the noombat-chatmail container.
#
# 1. Substitutes MAIL_DOMAIN in Postfix and Dovecot configuration.
# 2. Initialises empty Postfix hash maps if they do not exist.
# 3. Creates self-signed TLS certificates if none are mounted.
# 4. Hands off to s6-overlay (/init).

set -e

: "${MAIL_DOMAIN:?MAIL_DOMAIN must be set}"

echo "[entrypoint] configuring for domain: ${MAIL_DOMAIN}"

# ..... SUBSTITUTE MAIL_DOMAIN .....

sed -i "s/MAIL_DOMAIN/${MAIL_DOMAIN}/g" /etc/postfix/main.cf
sed -i "s/MAIL_DOMAIN/${MAIL_DOMAIN}/g" /etc/dovecot/dovecot.conf

# ..... FILTERMAIL CONTENT FILTER .....

# Append the filtermail pipe service to master.cf if it has not
# already been appended (idempotent across container restarts).
if ! grep -q "^filtermail" /etc/postfix/master.cf 2>/dev/null; then
    echo "" >> /etc/postfix/master.cf
    cat /etc/postfix/master.cf.filtermail >> /etc/postfix/master.cf
    echo "[entrypoint] appended filtermail service to master.cf"
fi

# ..... INITIALISE POSTFIX MAPS .....

# Ensure the moderation access map files exist (they are managed by
# the noombat-chatmail-admin sidecar at runtime).
for mapfile in \
    /etc/postfix/noombat_recipient_access \
    /etc/postfix/noombat_sender_access \
    /etc/postfix/noombat_transport_maps; do
    if [ ! -f "${mapfile}" ]; then
        touch "${mapfile}"
    fi
    postmap "${mapfile}" 2>/dev/null || true
done

# ..... TLS CERTIFICATES .....

# If no certificate is mounted, generate one for development. Production
# deployments should mount a real certificate.
#
# A local CA and a leaf signed by it, not one self-signed certificate.
# `openssl req -x509` marks what it produces `CA:TRUE`, and a client
# offered a CA certificate as the server's own rejects it: rustls calls
# that `CaUsedAsEndEntity`, and no amount of trusting it helps, because a
# CA certificate cannot be the leaf. The CA goes where the compose file
# shares it with Noombat, which trusts it through `SSL_CERT_FILE` exactly
# as the federation stack trusts Caddy's internal CA.
CHATMAIL_CA_DIR=/etc/ssl/chatmail-ca
if [ ! -f /etc/ssl/certs/chatmail.pem ]; then
    echo "[entrypoint] generating a local CA and a leaf certificate for ${MAIL_DOMAIN}"
    mkdir -p /etc/ssl/certs /etc/ssl/private "$CHATMAIL_CA_DIR"

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/ssl/private/chatmail-ca.key \
        -out "$CHATMAIL_CA_DIR/ca.crt" \
        -days 365 \
        -subj "/CN=Chatmail local CA (${MAIL_DOMAIN})" 2>/dev/null

    # `subjectAltName` and not the common name alone: a modern TLS client
    # matches the hostname against the SAN and ignores CN entirely.
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
        "${MAIL_DOMAIN}" > /tmp/chatmail-leaf.ext

    openssl req -newkey rsa:2048 -nodes \
        -keyout /etc/ssl/private/chatmail.key \
        -out /tmp/chatmail.csr \
        -subj "/CN=${MAIL_DOMAIN}" 2>/dev/null

    openssl x509 -req -in /tmp/chatmail.csr \
        -CA "$CHATMAIL_CA_DIR/ca.crt" \
        -CAkey /etc/ssl/private/chatmail-ca.key \
        -CAcreateserial \
        -out /etc/ssl/certs/chatmail.pem \
        -days 365 \
        -extfile /tmp/chatmail-leaf.ext 2>/dev/null

    # Serve the chain, so a client holding only the CA still builds a path.
    cat "$CHATMAIL_CA_DIR/ca.crt" >> /etc/ssl/certs/chatmail.pem

    rm -f /tmp/chatmail.csr /tmp/chatmail-leaf.ext
    chmod 640 /etc/ssl/private/chatmail.key /etc/ssl/private/chatmail-ca.key
    # World-readable: Noombat reads it from a shared volume as non-root.
    chmod 644 "$CHATMAIL_CA_DIR/ca.crt"
fi

# ..... DKIM .....

# Generate the signing key on first boot and write the tables that
# opendkim.conf points at. Without these, opendkim has nothing to sign
# with; without opendkim.conf it would also be listening on a unix
# socket while Postfix dials inet:localhost:8891.
#
# The selector is `noombat`, which must match the TXT record name
# printed below.
DKIM_DIR=/etc/opendkim
DKIM_SELECTOR=noombat

if [ ! -f "${DKIM_DIR}/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.private" ]; then
    echo "[entrypoint] generating DKIM key for ${MAIL_DOMAIN}"
    mkdir -p "${DKIM_DIR}/keys/${MAIL_DOMAIN}" /run/opendkim
    opendkim-genkey \
        --directory="${DKIM_DIR}/keys/${MAIL_DOMAIN}" \
        --selector="${DKIM_SELECTOR}" \
        --domain="${MAIL_DOMAIN}" \
        --bits=2048

    printf '%s._domainkey.%s %s:%s:%s\n' \
        "${DKIM_SELECTOR}" "${MAIL_DOMAIN}" \
        "${MAIL_DOMAIN}" "${DKIM_SELECTOR}" \
        "${DKIM_DIR}/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.private" \
        > "${DKIM_DIR}/KeyTable"
    printf '*@%s %s._domainkey.%s\n' \
        "${MAIL_DOMAIN}" "${DKIM_SELECTOR}" "${MAIL_DOMAIN}" \
        > "${DKIM_DIR}/SigningTable"
    printf '127.0.0.1\n::1\nlocalhost\n%s\n' "${MAIL_DOMAIN}" \
        > "${DKIM_DIR}/TrustedHosts"

    # Publish this before the relay is used, or every message is signed
    # with a key no resolver can find, which verifies worse than not
    # signing at all.
    echo "[entrypoint] ..... DKIM DNS record, publish this TXT record ....."
    cat "${DKIM_DIR}/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.txt"
    echo "[entrypoint] ..... end DKIM DNS record ....."
fi

chown -R opendkim:opendkim "${DKIM_DIR}" /run/opendkim
chmod 600 "${DKIM_DIR}/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.private"

# ..... PERMISSIONS .....

chown -R vmail:vmail /home/vmail

# ..... HAND OFF TO S6-OVERLAY .....

echo "[entrypoint] starting s6-overlay"
exec /init "$@"
