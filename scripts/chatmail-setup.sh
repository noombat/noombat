#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# Noombat Chatmail setup wizard (CLI).
#
# Verifies DNS records and outbound port 25 availability for the
# Chatmail relay before the instance is deployed.
#
# Usage:
#   scripts/chatmail-setup.sh <chatmail_domain>
#
# Example:
#   scripts/chatmail-setup.sh chat.noombat.social
#
# Prerequisites:
#   dig (dnsutils / bind-utils), nc (netcat-openbsd / nmap-ncat)
#
# Exit codes:
#   0: all checks passed.
#   1: one or more checks failed (details printed to stderr).

set -euo pipefail

# ..... COLOUR OUTPUT .....

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

pass()  { printf "${GREEN}  ✓ %s${RESET}\n" "$1"; }
fail()  { printf "${RED}  ✗ %s${RESET}\n" "$1" >&2; FAILURES=$((FAILURES + 1)); }
warn()  { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; }
info()  { printf "  → %s\n" "$1"; }
header(){ printf "\n${BOLD}%s${RESET}\n" "$1"; }

FAILURES=0

# ..... ARGUMENTS .....

if [ $# -lt 1 ]; then
    echo "Usage: $0 <chatmail_domain>" >&2
    echo "" >&2
    echo "Example: $0 chat.noombat.social" >&2
    exit 1
fi

DOMAIN="$1"

echo ""
echo "Noombat Chatmail Setup Wizard"
echo "============================="
echo ""
echo "Verifying DNS records and network configuration for: ${DOMAIN}"

# ..... PREREQUISITES .....

header "Prerequisites"

if command -v dig >/dev/null 2>&1; then
    pass "dig (DNS lookup tool) found"
else
    fail "dig not found (install dnsutils or bind-utils)"
    echo "" >&2
    echo "Cannot proceed without dig. Exiting." >&2
    exit 1
fi

if command -v nc >/dev/null 2>&1; then
    pass "nc (netcat) found"
    NC_CMD="nc"
elif command -v ncat >/dev/null 2>&1; then
    pass "ncat found"
    NC_CMD="ncat"
else
    warn "nc / ncat not found, port 25 check will be skipped"
    NC_CMD=""
fi

# ..... DNS: A / AAAA RECORDS .....

header "DNS: A / AAAA records for ${DOMAIN}"

A_RECORDS=$(dig +short A "${DOMAIN}" 2>/dev/null || true)
AAAA_RECORDS=$(dig +short AAAA "${DOMAIN}" 2>/dev/null || true)

if [ -n "${A_RECORDS}" ]; then
    for ip in ${A_RECORDS}; do
        pass "A record: ${ip}"
    done
else
    fail "No A record found for ${DOMAIN}"
fi

if [ -n "${AAAA_RECORDS}" ]; then
    for ip in ${AAAA_RECORDS}; do
        pass "AAAA record: ${ip}"
    done
else
    warn "No AAAA record found for ${DOMAIN} (optional but recommended)"
fi

# ..... DNS: MX RECORD .....

header "DNS: MX record for ${DOMAIN}"

MX_RECORDS=$(dig +short MX "${DOMAIN}" 2>/dev/null || true)

if [ -n "${MX_RECORDS}" ]; then
    while IFS= read -r mx; do
        pass "MX: ${mx}"
    done <<< "${MX_RECORDS}"

    # Chatmail relays should have the MX pointing to themselves.
    if echo "${MX_RECORDS}" | grep -qi "${DOMAIN}"; then
        pass "MX points to ${DOMAIN} (self-referential, as expected)"
    else
        warn "MX does not point to ${DOMAIN}. Chatmail relays typically point MX to themselves"
    fi
else
    fail "No MX record found for ${DOMAIN}"
    info "Add an MX record: ${DOMAIN}. IN MX 10 ${DOMAIN}."
fi

# ..... DNS: DKIM TXT RECORD .....

header "DNS: DKIM TXT record"

# Chatmail uses a default DKIM selector. Check common selectors.
DKIM_FOUND=false
for selector in "dkim" "mail" "default" "selector1"; do
    DKIM_NAME="${selector}._domainkey.${DOMAIN}"
    DKIM_TXT=$(dig +short TXT "${DKIM_NAME}" 2>/dev/null || true)
    if [ -n "${DKIM_TXT}" ]; then
        pass "DKIM TXT record found at ${DKIM_NAME}"
        DKIM_FOUND=true
        break
    fi
done

if [ "${DKIM_FOUND}" = false ]; then
    fail "No DKIM TXT record found for ${DOMAIN}"
    info "Generate a DKIM key and publish a TXT record at <selector>._domainkey.${DOMAIN}"
    info "Example: opendkim-genkey -s dkim -d ${DOMAIN}"
fi

# ..... OUTBOUND PORT 25 .....

header "Network: outbound port 25"

if [ -n "${NC_CMD}" ]; then
    # Test connectivity to several well-known MX hosts on port 25.
    # Success on any one confirms outbound port 25 is open.
    PORT25_OK=false
    for test_host in \
        "gmail-smtp-in.l.google.com" \
        "mx1.hotmail.com" \
        "mta5.am0.yahoodns.net"; do
        if ${NC_CMD} -z -w 5 "${test_host}" 25 2>/dev/null; then
            pass "Outbound port 25 is open (tested against ${test_host})"
            PORT25_OK=true
            break
        fi
    done
    if [ "${PORT25_OK}" = false ]; then
        fail "Outbound port 25 appears blocked (tested gmail, hotmail, yahoo)"
        info "Many cloud providers block port 25 by default."
        info "Hetzner: port 25 is available after account maturation and a limit request."
        info "         Dedicated servers have port 25 open by default."
        info "DigitalOcean: submit a support ticket to request port 25."
        info "OVH: port 25 is open by default on dedicated servers."
    fi
else
    warn "Skipping port 25 check (nc / ncat not available)"
fi

# ..... INBOUND PORT 25 .....

header "Network: inbound port 25 (self-test)"

if [ -n "${A_RECORDS}" ] && [ -n "${NC_CMD}" ]; then
    FIRST_IP=$(echo "${A_RECORDS}" | head -1)
    if ${NC_CMD} -z -w 5 "${FIRST_IP}" 25 2>/dev/null; then
        pass "Inbound port 25 is reachable on ${FIRST_IP}"
    else
        warn "Inbound port 25 not reachable on ${FIRST_IP} (may not be running yet)"
        info "Ensure your firewall allows inbound TCP port 25 from the internet."
    fi
else
    warn "Skipping inbound port 25 check"
fi

# ..... IMAP (993) AND SMTP SUBMISSION (465) .....

header "Network: IMAP (993) and SMTP submission (465)"

if [ -n "${A_RECORDS}" ] && [ -n "${NC_CMD}" ]; then
    FIRST_IP=$(echo "${A_RECORDS}" | head -1)
    for port in 993 465; do
        if ${NC_CMD} -z -w 5 "${FIRST_IP}" "${port}" 2>/dev/null; then
            pass "Port ${port} reachable on ${FIRST_IP}"
        else
            warn "Port ${port} not reachable on ${FIRST_IP} (may not be running yet)"
        fi
    done
else
    warn "Skipping port checks (no A record or nc not available)"
fi

# ..... SUMMARY .....

header "Summary"

if [ "${FAILURES}" -eq 0 ]; then
    printf "${GREEN}${BOLD}All checks passed.${RESET}\n"
    echo ""
    echo "Next steps:"
    echo "  1. If you have not yet registered this Chatmail domain in the"
    echo "     Noombat project allowlist, do so before inter-instance"
    echo "     messaging will function."
    echo "  2. Start the Compose stack:"
    echo "     NOOMBAT_DOMAIN=<your_domain> docker compose up -d"
    echo ""
    exit 0
else
    printf "${RED}${BOLD}${FAILURES} check(s) failed.${RESET}\n" >&2
    echo "" >&2
    echo "Resolve the issues above before deploying the Chatmail relay." >&2
    echo "" >&2
    exit 1
fi
