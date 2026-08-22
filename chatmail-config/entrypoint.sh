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

# The setting that invokes the filter belongs on the smtpd listeners,
# never in main.cf. The 465 listener carries it in the snippet appended
# above; the inbound listener on 25 and the `pickup` service come from
# the base image's master.cf, so they are edited here instead.
#
# A global `content_filter` in main.cf loops. `cleanup` applies it on
# every submission path, `pickup` included, and filtermail re-injects
# accepted mail through `pickup`, so the message returns to the filter
# until Postfix bounces it for too many hops. main.cf carries the
# measurement.
#
# `no_milters` on `pickup` because OpenDKIM already signed the message
# when it arrived on 25 or 465. Without this, re-injection runs the
# milter a second time and every delivered message carries two
# signatures over the same body.
#
# `postconf -P` rather than an edit in place: it replaces the parameter
# when it is already set, which makes this idempotent across restarts,
# and it distinguishes `smtp/inet`, the listener, from `smtp/unix`, the
# outbound client transport that must not filter anything.
postconf -P "smtp/inet/content_filter=filtermail:dummy"
postconf -P "pickup/unix/receive_override_options=no_milters"

# ..... POSTFIX CHROOT AND QUEUE DIRECTORIES .....

# Debian runs smtpd, cleanup, pickup and the outbound smtp client
# chrooted to /var/spool/postfix, and the base image ships that
# directory with an empty `etc`. Nothing inside the chroot can resolve a
# name until these are copied in, which breaks two separate things: the
# milter address, and every peer domain in transport_maps, written as
# `smtp:[domain]` and still needing an address record.
#
# Measured in this image, with the chroot `etc` empty: every connection
# on port 25 is answered `451 4.7.1 Service unavailable`, because
# Postfix cannot reach OpenDKIM and `milter_default_action` is
# `tempfail`. The relay accepts nothing while every process reports
# itself healthy. Copying these in makes the same submission succeed.
#
# glibc 2.36 in the base image resolves `files` and `dns` from libc
# itself, so no NSS module has to be copied alongside them.
#
# Copies, so a later change to the container's resolv.conf does not
# reach Postfix until the container restarts. That is the same bargain
# Postfix's chroot makes on any host.
mkdir -p /var/spool/postfix/etc
for chrootfile in /etc/resolv.conf /etc/hosts /etc/services /etc/nsswitch.conf; do
    if [ -f "${chrootfile}" ]; then
        cp -f "${chrootfile}" /var/spool/postfix/etc/
    fi
done

# The base image's spool is missing the `hold` and `trace` queues, and
# missing is fatal rather than degraded: `mailq`, `postqueue -p` and
# `postsuper` each exit non-zero with `scan_dir_push: open directory
# hold`, so an operator cannot inspect, flush or delete anything.
# `postfix check` creates whatever is absent.
postfix check

# ..... INITIALISE POSTFIX MAPS .....

# Ensure the moderation access map files exist (they are managed by
# the noombat-chatmail-admin sidecar at runtime).
for mapfile in \
    /etc/postfix/noombat_recipient_access \
    /etc/postfix/noombat_sender_access \
    /etc/postfix/noombat_transport_maps \
    /etc/postfix/noombat_sender_domains; do
    if [ ! -f "${mapfile}" ]; then
        touch "${mapfile}"
    fi
    postmap "${mapfile}" 2>/dev/null || true
done

# ..... TLS CERTIFICATES .....

# A development domain may generate its own certificate. Anything else
# must be given one, and is refused rather than started without one.
#
# The refusal is the point. A relay serving a certificate no client will
# accept looks healthy from the outside: Postfix and Dovecot start, the
# ports answer, and the failure appears only at the client, as a TLS
# error with no matching entry in any log here. Refusing to start puts
# the cause in the operator's terminal at the moment they cause it.
#
# Keyed off MAIL_DOMAIN because that is what this container is given.
# NOOMBAT_DOMAIN is not visible here: the compose service passes
# MAIL_DOMAIN, the admin secret, host and port, and the allowlist URL,
# and Dockerfile.chatmail sets no ENV at all.
is_development_domain() {
    case "$1" in
        localhost | *.localhost | *.local | *.test | *.example | *.invalid) return 0 ;;
        *) return 1 ;;
    esac
}

# If no certificate is mounted, generate one for development. Production
# deployments must mount a real certificate.
#
# A local CA and a leaf signed by it, not one self-signed certificate.
# `openssl req -x509` marks what it produces `CA:TRUE`, and a client
# offered a CA certificate as the server's own rejects it: rustls calls
# that `CaUsedAsEndEntity`, and no amount of trusting it helps, because a
# CA certificate cannot be the leaf.
CHATMAIL_CA_DIR=/etc/ssl/chatmail-ca

# When Caddy is the issuer, wait for it rather than failing on the first
# boot of a new deployment. Caddy obtains the certificate asynchronously
# once `chat.` resolves, so for a minute or two after `compose up` there
# is nothing to import. Waiting says so once; the alternative is a
# restart loop whose log line is the refusal below, which reads like a
# misconfiguration rather than a normal first boot.
if [ ! -f /etc/ssl/certs/chatmail.pem ] && [ -n "${CHATMAIL_CADDY_DATA:-}" ]; then
    echo "[entrypoint] waiting for Caddy to issue a certificate for ${MAIL_DOMAIN}"
    waited=0
    until /usr/local/bin/cert-watch --import >/dev/null 2>&1; do
        if [ "$waited" -ge "${CHATMAIL_CERT_WAIT_SECS:-300}" ]; then
            echo "[entrypoint] FATAL: Caddy issued no certificate for ${MAIL_DOMAIN}" >&2
            echo "[entrypoint]   Check that ${MAIL_DOMAIN} resolves to this host and that" >&2
            echo "[entrypoint]   port 80 reaches Caddy, which is what HTTP-01 validates on." >&2
            echo "[entrypoint]   Caddy's own log names the ACME failure." >&2
            exit 1
        fi
        sleep 5
        waited=$((waited + 5))
    done
    echo "[entrypoint] imported the certificate Caddy issued (waited ${waited}s)"
fi

if [ ! -f /etc/ssl/certs/chatmail.pem ]; then
    if ! is_development_domain "${MAIL_DOMAIN}"; then
        echo "[entrypoint] FATAL: no certificate for ${MAIL_DOMAIN}" >&2
        echo "[entrypoint]   Expected a PEM chain at /etc/ssl/certs/chatmail.pem and a key" >&2
        echo "[entrypoint]   at /etc/ssl/private/chatmail.key, mounted from the host or from" >&2
        echo "[entrypoint]   the chatmail-tls volume that Caddy writes." >&2
        echo "[entrypoint]   Refusing to start: a generated certificate here would be trusted" >&2
        echo "[entrypoint]   by nothing, and the relay would look healthy while every client" >&2
        echo "[entrypoint]   failed the handshake." >&2
        exit 1
    fi
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

# Renewal is handled by the `cert-watch` s6 service, not from here: a
# background job started before `exec /init` is supervised by nothing.

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

    # opendkim-genkey writes PKCS#8 when built against OpenSSL 3, and
    # OpenDKIM 2.11 loads only PKCS#1, so unconverted no message can be
    # signed. The public key is unchanged, so the TXT record below still
    # matches.
    DKIM_KEY="${DKIM_DIR}/keys/${MAIL_DOMAIN}/${DKIM_SELECTOR}.private"
    openssl rsa -in "${DKIM_KEY}" -out "${DKIM_KEY}.pkcs1" -traditional 2>/dev/null
    mv "${DKIM_KEY}.pkcs1" "${DKIM_KEY}"

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

# ..... SYSLOG .....

# Nothing in this image creates /dev/log, so every daemon that logs
# through syslog logs into nothing. Postfix has `maillog_file` to route
# around that; OpenDKIM has no equivalent.
#
# A collector rather than a syslog daemon because the image has neither,
# and perl is already here. Backgrounded before the s6 handoff so it
# inherits the container's stdout.
perl -e '
use Socket; use IO::Handle;
unlink "/dev/log";
socket(my $sock, PF_UNIX, SOCK_DGRAM, 0) or die "socket: $!";
bind($sock, sockaddr_un("/dev/log")) or die "bind: $!";
chmod 0666, "/dev/log";
STDOUT->autoflush(1);
while (1) {
    next unless defined recv($sock, my $line, 8192, 0);
    $line =~ s/\0+$//;
    print "$line\n";
}
' &

# Give the socket a moment to exist before any daemon opens it.
sleep 1

# ..... HAND OFF TO S6-OVERLAY .....

echo "[entrypoint] starting s6-overlay"
exec /init "$@"
