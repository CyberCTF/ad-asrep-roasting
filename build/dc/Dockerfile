# Samba, acting as an Active Directory Domain Controller, in a single Linux container.
# It provisions the realm NORTH.SEVENKINGDOMS.LOCAL at first start (idempotent), plants a
# handful of ordinary domain users plus one account with Kerberos pre-authentication disabled
# (jon.snow, UF_DONT_REQUIRE_PREAUTH, weak RC4 key), and a vault share only that account may
# read. The AS-REP roasting client tooling (impacket, hashcat) ships in the image so the lab's
# check can prove the path from inside the DC.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Preseed krb5 so its package install never prompts.
RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string NORTH.SEVENKINGDOMS.LOCAL" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient ldb-tools \
        winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config ldap-utils \
        python3 python3-venv \
        hashcat pocl-opencl-icd ocl-icd-libopencl1 \
        dnsutils procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    # The AD DC runs as the single `samba` process, never the standalone smbd/nmbd/winbind
    # units, so make sure none of those can start on their own.
    rm -f /etc/samba/smb.conf

# impacket (pinned) in its own venv: AS-REP roasting is GetNPUsers.py, an AS-REQ *without*
# pre-authentication, which (unlike kerberoast's TGS-REQ) interoperates cleanly with the Samba
# KDC. The self-contained check reuses it, and a student runs the same GetNPUsers.py from here.
RUN set -eux; \
    python3 -m venv /opt/impacket-venv; \
    /opt/impacket-venv/bin/pip install --no-cache-dir wheel; \
    /opt/impacket-venv/bin/pip install --no-cache-dir "impacket==0.13.1"; \
    test -x /opt/impacket-venv/bin/GetNPUsers.py

COPY vault-share.conf /opt/asrep/vault-share.conf
COPY wordlist.txt     /opt/asrep/wordlist.txt
COPY users.txt        /opt/asrep/users.txt
COPY asrep.py         /opt/asrep/asrep.py
COPY check.sh         /opt/asrep/check.sh
COPY entrypoint.sh    /opt/asrep/entrypoint.sh
RUN chmod +x /opt/asrep/entrypoint.sh /opt/asrep/check.sh /opt/asrep/asrep.py

# hashcat's first run JIT-compiles its OpenCL kernels (~minutes on a CPU backend). Do that once
# at build time on a dummy AS-REP hash so the compiled kernels are baked into
# /root/.cache/hashcat; the lab's check then cracks in seconds. Keep HOME fixed so the cache is
# found at run time.
ENV HOME=/root
RUN set -eux; \
    dummy='$krb5asrep$23$jon.snow@NORTH.SEVENKINGDOMS.LOCAL:'"$(printf 'a%.0s' $(seq 1 32))"'$'"$(printf 'b%.0s' $(seq 1 64))"; \
    printf '%s\n' "$dummy" > /tmp/warm.hash; \
    hashcat -m 18200 -a 0 -O --force --self-test-disable \
      --potfile-path=/tmp/warm.pot /tmp/warm.hash /opt/asrep/wordlist.txt || true; \
    rm -f /tmp/warm.hash /tmp/warm.pot; \
    test -d /root/.cache/hashcat/kernels

# AD/Kerberos surface.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp

CMD ["/opt/asrep/entrypoint.sh"]
