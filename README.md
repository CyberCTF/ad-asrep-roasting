# AS-REP Roasting (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**LAKESIDE.LAB** (Lakeside Regional Hospital, a healthcare provider) — no Windows VMs. It
provisions a set of ordinary hospital staff users plus one legacy document-scanner service
account whose Kerberos pre-authentication is disabled (`svc-scanner`, `UF_DONT_REQUIRE_PREAUTH`,
with a weak RC4 key), and an `imaging` share only `svc-scanner` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

An account with Kerberos pre-authentication disabled (`userAccountControl` bit
`DONT_REQ_PREAUTH`) has the KDC return an AS-REP — the reply encrypted with the account's own
long-term key — which can be cracked offline. The real-world technique needs no credentials:

1. AS-REP roast a username list with impacket:
   `GetNPUsers.py LAKESIDE.LAB/ -usersfile users.txt -no-pass -dc-ip <dc> -format hashcat`
   → against a Windows AD DC, a `$krb5asrep$23$svc-scanner@...` hash for the account missing pre-auth.
2. Crack it offline: `hashcat -m 18200 asrep.hash rockyou.txt`.
3. Read the flag: `smbclient //dc/imaging -U 'LAKESIDE\svc-scanner%<cracked>' -c 'get flag.txt'`.

### Samba caveat (important)

This DC is **Samba**, and — like the sibling kerberoasting lab, where impacket's TGS request is
rejected with `KRB_AP_ERR_INAPP_CKSUM` — Samba's Kerberos has a quirk here too: its KDC
**enforces pre-authentication for every account, even one flagged `DONT_REQ_PREAUTH`**. A
pre-auth-less `GetNPUsers -no-pass` therefore returns `KDC_ERR_PREAUTH_REQUIRED` and yields no
hash (verified against Samba 4.17 and 4.19; the source maps the flag in `uf2SDBFlags`, but the
KDC still demands pre-auth at runtime).

The material you crack — the AS-REP `enc-part` — is emitted by the KDC in *any* successful AS
exchange, so the roastable `$krb5asrep$23$` hash is retrieved with a native, RC4-pinned
*pre-authenticated* AS-REQ ([`asrep.py`](build/dc/asrep.py)) and cracked with `hashcat -m 18200`
exactly as above. The technique, the hash, and the crack are unchanged; only the way the hash
leaves the Samba KDC differs. The lab's self-check drives this native path end to end.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
