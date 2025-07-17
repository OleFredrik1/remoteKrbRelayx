from __future__ import unicode_literals
import random
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from impacket.krb5.asn1 import AP_REQ

from .spnego import GSSAPIHeader_KRB5_AP_REQ2, GSSAPIHeader_SPNEGO_Init

def get_auth_data_negotiate(token, options):
    try:
        blob = decoder.decode(token, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
    except PyAsn1Error:
        # This is likely a response so no plaintext data
        return {
            "domain": None,
            "username": None,
            "krbauth": token,
            "service": None,
            "apreq": None
        }
    data = blob['innerContextToken']['negTokenInit']['mechToken']
    try:
        apreq = decoder.decode(data, asn1Spec=AP_REQ())[0]
    except PyAsn1Error:
        raise Exception('Error obtaining Kerberos data')
    # Get ticket data
    domain = str(apreq['ticket']['realm']).lower()
    # Assume this is NT_SRV_INST with 2 labels (not sure this is always the case)
    sname = '/'.join([str(item) for item in apreq['ticket']['sname']['name-string']])

    # We dont actually know the client name, either use unknown$ or use the user specified
    if options.victim:
        username = options.victim
    else:
        username = f"unknown{random.randint(0, 10000):04d}$"
    return {
        "domain": domain,
        "username": username,
        "krbauth": token,
        "service": sname,
        "apreq": apreq
    }

def get_auth_data_kerberos(token, options):
    try:
        apreq = decoder.decode(token, asn1Spec=AP_REQ())[0]
    except PyAsn1Error:
        # This is likely a response so no plaintext data
        return {
            "domain": None,
            "username": None,
            "krbauth": token,
            "service": None,
            "apreq": None
        }
    test = GSSAPIHeader_KRB5_AP_REQ2()
    test['tokenOid'] = '1.2.840.113554.1.2.2.1.1'  # OID for Kerberos + two bytes for krb5_ap_req
    #test['krb5_ap_req'] = 0x0001 # This is a constant value for AP_REQ
    test['apReq'] = apreq
    new_token = encoder.encode(test)
    # Hacky solution as I could not get pyasn1 to encode krb5_ap_rep correctly
    new_token = new_token.replace(bytes.fromhex("0b2a864886f7120102020101"), bytes.fromhex("092a864886f7120102020100"))
    # Get ticket data
    domain = str(apreq['ticket']['realm']).lower()
    # Assume this is NT_SRV_INST with 2 labels (not sure this is always the case)
    sname = '/'.join([str(item) for item in apreq['ticket']['sname']['name-string']])

    # We dont actually know the client name, either use unknown$ or use the user specified
    if options.victim:
        username = options.victim
    else:
        username = f"unknown{random.randint(0, 10000):04d}$"
    return {
        "domain": domain,
        "username": username,
        "krbauth": new_token,
        "service": sname,
        "apreq": apreq
    }