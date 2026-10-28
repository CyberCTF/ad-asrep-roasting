#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm LAKESIDE.LAB once (skipped on restart),
#   2. creates a handful of ordinary hospital staff users and one legacy service account with
#      Kerberos pre-authentication disabled (svc-scanner, UF_DONT_REQUIRE_PREAUTH + weak RC4 key),
#   3. plants the flag in a share only svc-scanner may read,
#   4. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
#
# Scenario: Lakeside Regional Hospital. A legacy document-scanner integration still runs under a
# dedicated service account (svc-scanner) whose Kerberos pre-authentication was disabled for an
# old app, and whose password is a weak, wordlist-crackable word.
set -euo pipefail

REALM="LAKESIDE.LAB"
DOMAIN="LAKESIDE"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Lakeside2024"

# The AS-REP roastable account: Kerberos pre-auth disabled, and a weak, wordlist-crackable
# password. Policy-compliant (complexity on) but trivially guessable.
NOPREAUTH_USER="svc-scanner"
NOPREAUTH_PASS="Scanner2021"

# Ordinary hospital staff users. They have pre-authentication ON, so they are decoys in the
# username list: AS-REP roasting them yields nothing. Their passwords are strong and uninteresting.
declare -a DECOYS=(j.okoro a.mensah r.kaplan d.ferreira l.nguyen)

PRIVATE_DIR="/var/lib/samba/private"
STAMP="${PRIVATE_DIR}/.isoloom-provisioned"

# userAccountControl for a normal, enabled account that does NOT require Kerberos pre-auth:
#   0x0200 NORMAL_ACCOUNT | 0x400000 DONT_REQ_PREAUTH = 0x400200 = 4194816
UAC_NOPREAUTH=4194816

log() { echo "[dc] $*" >&2; }

rand_pass() { echo "Zz9$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"; }

if [ ! -f "${STAMP}" ]; then
  log "provisioning ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # posix:eadb keeps NT ACLs in a tdb instead of security.* xattrs, so provisioning and the
  # file server work in an unprivileged container (no CAP_SYS_ADMIN). "ldap server require
  # strong auth = no" lets the student enumerate over plain LDAP from the attack box.
  # Both --options persist into the generated smb.conf, so the running daemon uses them too.
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc \
    --adminpass="${ADMIN_PASS}" \
    --option="posix:eadb=/var/lib/samba/eadb.tdb" \
    --option="ldap server require strong auth = no" >/dev/null

  # Kerberos client config and resolver point the DC at its own internal DNS.
  cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

  # Publish the imaging share that guards the flag.
  cat /opt/asrep/vault-share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch lakeside.lab\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.lakeside.lab' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.lakeside.lab dc\n' >> /etc/hosts 2>/dev/null || true

# Accounts are created offline against the local sam.ldb, so this works whether or not the
# samba process is already running.

# Ordinary (pre-auth ON) decoy users.
for u in "${DECOYS[@]}"; do
  if ! samba-tool user list 2>/dev/null | grep -qx "${u}"; then
    log "creating decoy user ${u}"
    samba-tool user create "${u}" "$(rand_pass)" >/dev/null
  fi
done

# The AS-REP roastable account.
if ! samba-tool user list 2>/dev/null | grep -qx "${NOPREAUTH_USER}"; then
  log "creating pre-auth-disabled user ${NOPREAUTH_USER}"
  samba-tool user create "${NOPREAUTH_USER}" "${NOPREAUTH_PASS}" \
    --description="Legacy document-scanner integration (pre-auth disabled for an old app)" >/dev/null
fi

# Disable Kerberos pre-authentication and force RC4 (etype 23) on svc-scanner, both written
# offline against sam.ldb (as the base lab does for enctypes): the running KDC enforces
# samba's ldap constraints on userAccountControl, but an offline ldbmodify does not.
#   - userAccountControl |= DONT_REQ_PREAUTH  -> the KDC returns an AS-REP with no pre-auth,
#   - msDS-SupportedEncryptionTypes = 4 (RC4) -> the AS-REP is the classic $krb5asrep$23$
#     hash (hashcat 18200) rather than AES.
NOPREAUTH_DN="$(samba-tool user show "${NOPREAUTH_USER}" 2>/dev/null | awk -F': ' '/^dn:/{print $2; exit}')"
if [ -n "${NOPREAUTH_DN}" ]; then
  cat > /tmp/asrep.ldif <<EOF
dn: ${NOPREAUTH_DN}
changetype: modify
replace: userAccountControl
userAccountControl: ${UAC_NOPREAUTH}
-
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 4
EOF
  ldbmodify -H "${PRIVATE_DIR}/sam.ldb" /tmp/asrep.ldif >/dev/null 2>&1 || true
  rm -f /tmp/asrep.ldif
fi

# Passwords never expire, so the lab behaves the same on day 1 and day 60.
samba-tool user setexpiry "${NOPREAUTH_USER}" --noexpiry >/dev/null 2>&1 || true
for u in "${DECOYS[@]}"; do
  samba-tool user setexpiry "${u}" --noexpiry >/dev/null 2>&1 || true
done

# Plant the flag inside the imaging share. CTF_FLAG_MAIN is delivered by the launcher at /ctf/flag
# (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/imaging
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/imaging/flag.txt
else
  printf 'FLAG{dev-asrep-lakeside}\n' > /srv/imaging/flag.txt
fi
chmod 0444 /srv/imaging/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
