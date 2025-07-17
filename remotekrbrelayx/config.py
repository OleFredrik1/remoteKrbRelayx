from remotekrbrelayx.krbrelayx.lib.utils.config import KrbRelayxConfig

class RemoteKrbRelayxConfig(KrbRelayxConfig):
    def __init__(self):
        KrbRelayxConfig.__init__(self)

        self.spn = None
        self.authenticationType = None
        self.alternateServer = None
        self.alternateRpcPort = None
        self.alternateSmbPipe = None
        self.alternateProtocol = None
        self.coerceTo = None
    
    def setSPN(self, spn):
        self.spn = spn

    def setAuthenticationType(self, auth_type):
        self.authenticationType = auth_type
    
    def setAlternateServer(self, server):
        self.alternateServer = server

    def setAlternateRpcPort(self, port):
        self.alternateRpcPort = port

    def setAlternateSmbPipe(self, pipe):
        self.alternateSmbPipe = pipe

    def setAlternateProtocol(self, protocol):
        self.alternateProtocol = protocol
    
    def setCoerceTo(self, coerce_to):
        self.coerceTo = coerce_to
