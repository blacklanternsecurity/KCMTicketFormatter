#!/usr/bin/env python3

"""
   Kerberos Payload Conversion Tool
   Carson Sallis <carson.sallis@blacklanternsecurity.com>

   Description: This tools takes the output from https://github.com/fireeye/SSSDKCMExtractor
   and turns it into properly formatted CCACHE files for use with Windows systems.
"""

import argparse
import ast
import base64
import binascii
import logging
import re
import sys
import traceback

#Set up logging
console = logging.StreamHandler(sys.stdout)
logging.getLogger('KCMTicketFormatter').handlers = [console]
log = logging.getLogger('KCMTicketFormatter')
log.setLevel(logging.INFO)

#Static variables
PAYLOAD_HEADER = b'0504000c00010008ffffffff00000000'
KRBTGT = b'066b7262746774'

def format_payload(args):

    #Check for verbosity to display debug messages
    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:


        #Base64 decode the payload before attempting to manipulate the data
        filename = args.file[0]
        log.info("[+] Opening file for input: %s", args.file[0])
        encrypted_payload = open(filename, "r").read()
        log.info("[+] Decoding the base64 encoded payload from the DB")
        decoded_payload = base64.b64decode(encrypted_payload)
        h = binascii.hexlify(decoded_payload)
        log.debug("[~] Payload decoded to: %s", h)

        #Add necessary header to the beginning of the file
        h = PAYLOAD_HEADER + h
        log.info("[+] Adding CCACHE header to beginning")
        log.debug("[~] Payload with new header added: %s", h)

        #Replace btyecode b'0000000200000002' to b'0000000100000001'
        h = h.replace(b'0000000200000002', b'0000000100000001')
        log.info("[+] Formatting additional bytes")
        log.debug("[~] Payload with \"0000000200000002\" replace with \"0000000100000001\": %s", h)

        #Parse out the username and domain with offset included
        log.info("[+] Parsing out the username, domain, and their respective offsets")
        result = re.search(b'000000(.*)000000066b7262746774', h).group(1).split(b'0000000100000001000000')[1]
        domain_offset_hex = result[:2]
        log.debug("[~] Domain offset determined to be: %s in hex", domain_offset_hex)
        domain_offset_decimal = int(domain_offset_hex, base=16)
        log.debug("[~] Domain offset determined to be: %s in decimal", domain_offset_decimal)
        domain = (result[:2+domain_offset_decimal*2])
        log.debug("[~] Domain determined to be: %s in hex", domain)
        new_result = result.split(domain)[1]
        result2 = re.search(b'(?:00)+(.+)', new_result)
        username = result2.group(1)
        log.debug("[~] Username determined to be: %s in hex", username)

        #Find krbtgt offset and append data in front of it
        log.info("[+] Locating KRBTGT")
        parse = h.split(KRBTGT)
        new_h = parse[0] + username + b'0000000200000002000000' + domain + b'000000' + KRBTGT + parse[1] + KRBTGT + parse[2]
        log.debug("[~] Appended \"<usernameoffset><usernameinhex>0000000200000002000000<domainoffset><domaininhex>000000\" before krbtgt")

        #Convert domains to lowercase
        log.info("[+] Converting necessary instances of domain to lowercase")
        lowercase_domain = binascii.unhexlify(domain)
        x = bytearray(lowercase_domain)
        del x[0:1]
        lowercase_domain_bytes = bytes(x)
        lowercase_domain = domain_offset_hex + binascii.hexlify(lowercase_domain_bytes.lower())
        log.debug("[~] Lowercase domain determined to be %s in hex", lowercase_domain)
        parse = new_h.split(domain)
        new_h = parse[0] + domain + parse[1] + domain + parse[2] + domain + parse[3] + lowercase_domain + parse[4] + domain + parse[5] + lowercase_domain + parse[6]

        log.info("[+] Writing formatted ticket to file: \"%s\"", args.output)
        f = open(args.output, 'wb')
        log.debug("[~] Final payload being written to file: %s", binascii.unhexlify(new_h))
        f.write(binascii.unhexlify(new_h))
        f.close

    except KeyboardInterrupt:
        log.critical('[x] Interrupted')

    except Exception as e:
        if log.level <= logging.DEBUG:
            log.critical(traceback.format_exc())
        else:
            log.critical(f'Critical error (-v to debug): {e}')

    finally:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Format SSSD Raw Kerberos Payloads into CCACHE files.")
    parser.add_argument('-f', '--file', nargs=1, help='<Required> Specify path to SSSD Raw Kerberos Payload', required=True)
    parser.add_argument('-o', '--output', default='ticket.ccache', required=False, help='Specify name of file to output the ccache. Defaults to ticket.ccache')
    parser.add_argument('-v', '--verbose', action='store_true', required=False, help='Show debugging messages')

    return parser.parse_args()


def main():
    """Initial Function"""

    interrupted = False

    args = parse_args()

    format_payload(args)


if __name__ == '__main__':
    main()
