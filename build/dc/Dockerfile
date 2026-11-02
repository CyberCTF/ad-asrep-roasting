# Samba, acting as an Active Directory Domain Controller, in a single Linux container.
# It provisions the realm LAKESIDE.LAB at first start (idempotent), plants a handful of ordinary
# hospital staff users plus one legacy service account with Kerberos pre-authentication disabled
# (svc-scanner, UF_DONT_REQUIRE_PREAUTH, weak password), and an imaging share only that account
# may read. The AS-REP roasting client tooling (impacket) ships in the image so the lab's check
# can prove the path from inside the DC.
#
# Base: Fedora. Fedora builds Samba against the *MIT* Kerberos KDC, which honours
# UF_DONT_REQUIRE_PREAUTH -- so the classic no-pre-auth AS-REP roast (GetNPUsers -no-pass /
# nxc --asreproast) returns a hash here, exactly as against a Windows DC. Debian/Ubuntu build
# Samba against the Heimdal KDC, which ignores the flag and answers KDC_ERR_PREAUTH_REQUIRED, so
# the lab is unsolvable there -- this base is a hard requirement, not a preference. (Fedora is
# updated roughly yearly; the lab's image.yml rebuilds the image, so bump the tag when it EOLs.)
FROM fedora:43

RUN set -eux; \
    dnf install -y --setopt=install_weak_deps=False \
        samba samba-dc samba-client samba-common-tools ldb-tools \
        krb5-workstation \
        python3 python3-pip \
        bind-utils procps-ng iproute findutils diffutils gawk sed ca-certificates; \
    dnf clean all; \
    # The AD DC runs as the single `samba` process; make sure the standalone smb.conf a package
    # may drop doesn't make it start as a file server instead.
    rm -f /etc/samba/smb.conf

# impacket (pinned) in its own venv: the check roasts with GetNPUsers.py and cracks the AES AS-REP
# with crack.py; a student runs the same GetNPUsers.py / nxc from the attack box.
RUN set -eux; \
    python3 -m venv /opt/impacket-venv; \
    /opt/impacket-venv/bin/pip install --no-cache-dir wheel; \
    /opt/impacket-venv/bin/pip install --no-cache-dir "impacket==0.13.1"; \
    test -x /opt/impacket-venv/bin/GetNPUsers.py

COPY vault-share.conf /opt/asrep/vault-share.conf
COPY wordlist.txt     /opt/asrep/wordlist.txt
COPY users.txt        /opt/asrep/users.txt
COPY crack.py         /opt/asrep/crack.py
COPY check.sh         /opt/asrep/check.sh
COPY entrypoint.sh    /opt/asrep/entrypoint.sh
RUN chmod +x /opt/asrep/entrypoint.sh /opt/asrep/check.sh /opt/asrep/crack.py

ENV HOME=/root

# AD/Kerberos surface.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp

CMD ["/opt/asrep/entrypoint.sh"]
