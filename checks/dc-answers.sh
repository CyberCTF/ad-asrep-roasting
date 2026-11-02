#!/bin/sh
# The Lakeside DC is up: dc answers DNS, Kerberos, LDAP and SMB on the lab network. (A Windows DC
# can't be a check's `from:` host, so the end-to-end roast is proven in development on a hypervisor
# and taught in the briefing; this check confirms the domain is reachable.)
set -eu
for port in 53 88 389 445; do
  timeout 5 bash -c "exec 3<>/dev/tcp/10.30.10.10/$port"
done
echo "dc.lakeside.lab serves the domain"
