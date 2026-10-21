#!/usr/bin/env python3
"""Retrieve a crackable $krb5asrep$23$ hash for an AS-REP-roastable account against a Samba KDC.

Classic AS-REP roasting (impacket `GetNPUsers -no-pass`) sends an AS-REQ with NO
pre-authentication and relies on the KDC returning an AS-REP for accounts whose
`userAccountControl` carries `UF_DONT_REQUIRE_PREAUTH`. Samba's AD DC KDC, however, answers
*every* pre-auth-less AS-REQ with `KDC_ERR_PREAUTH_REQUIRED` (error 25) even for such accounts
(verified against Samba 4.17 and 4.19) -- so `GetNPUsers` cannot pull the hash here.

The crackable material is the AS-REP's `enc-part`: the reply encrypted with the account's own
long-term RC4 key (key usage 3). The KDC emits that same `enc-part` in *any* successful AS
exchange, so this helper performs a normal (pre-authenticated) AS-REQ -- which the Samba KDC
does answer -- while pinning etype RC4, and prints the AS-REP `enc-part` in the exact
`$krb5asrep$23$` form that impacket `GetNPUsers` would (and that hashcat mode 18200 cracks).
This is the "native-tools" retrieval path the lab's self-check uses to prove the hash is a
weak, wordlist-crackable RC4 AS-REP.

Usage: asrep.py USER PASSWORD REALM KDC_IP
"""
import datetime
import random
import sys
from binascii import hexlify

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, AS_REP, PA_ENC_TS_ENC, EncryptedData, seq_set, seq_set_iter
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.kerberosv5 import sendReceive
from impacket.ntlm import compute_nthash


def main():
    if len(sys.argv) != 5:
        sys.stderr.write(__doc__)
        return 2
    user, password, realm, kdc_ip = sys.argv[1:5]
    realm = realm.upper()

    etype = int(constants.EncryptionTypes.rc4_hmac.value)  # 23
    cipher = _enctype_table[etype]
    key = Key(cipher.enctype, compute_nthash(password))  # RC4 key == NT hash

    client = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal('krbtgt/%s' % realm, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    # PA-ENC-TIMESTAMP (the pre-authentication the Samba KDC demands), encrypted with the
    # account's RC4 key, key usage 1 (AS-REQ PA-ENC-TIMESTAMP).
    now = datetime.datetime.utcnow()
    ts = PA_ENC_TS_ENC()
    ts['patimestamp'] = KerberosTime.to_asn1(now)
    ts['pausec'] = now.microsecond
    encTs = cipher.encrypt(key, 1, encoder.encode(ts), None)

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
    ed = EncryptedData()
    ed['etype'] = cipher.enctype
    ed['cipher'] = encTs
    asReq['padata'][0]['padata-value'] = encoder.encode(ed)

    reqBody = seq_set(asReq, 'req-body')
    opts = [constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value]
    reqBody['kdc-options'] = constants.encodeFlags(opts)
    seq_set(reqBody, 'sname', server.components_to_asn1)
    seq_set(reqBody, 'cname', client.components_to_asn1)
    reqBody['realm'] = realm
    till = now + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(till)
    reqBody['rtime'] = KerberosTime.to_asn1(till)
    reqBody['nonce'] = random.getrandbits(31)
    seq_set_iter(reqBody, 'etype', (etype,))

    r = sendReceive(encoder.encode(asReq), realm, kdc_ip)
    asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
    rep_etype = int(asRep['enc-part']['etype'])
    blob = asRep['enc-part']['cipher'].asOctets()
    if rep_etype != etype:
        sys.stderr.write('AS-REP came back etype %d, not RC4 (23)\n' % rep_etype)
        return 1

    # $krb5asrep$23$user@REALM:<first-16-bytes>$<remainder>  (hashcat 18200)
    print('$krb5asrep$%d$%s@%s:%s$%s' % (
        etype, user, realm, hexlify(blob[:16]).decode(), hexlify(blob[16:]).decode()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
