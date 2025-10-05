import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT  # Import TXT for explicit construction
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


# --- Prepare Encryption Parameters ---
salt = b'Tandon'
# IMPORTANT: REPLACE THIS WITH YOUR ACTUAL NYU EMAIL
password = 'am16565@nyu.edu'  # Using the email from the error log for completion
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)
# The encrypted value is BYTES. We store the raw bytes in the DNS dictionary.
# We will handle the conversion/formatting in the server loop.
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        # Store as a tuple of strings for standard TXT records
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },

    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # TXT: Store the encrypted value as a tuple of BYTES!
        # TXT records technically store byte strings. This avoids string/quoting issues.
        dns.rdatatype.TXT: (encrypted_value,),
        # MX -> 10, mxa-00256a01.gslb.pphosted.com.
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        # AAAA -> 2001:0db8:85a3:0000:0000:8a2e:0373:7312
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        # NS -> ns1.nyu.edu.
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}


def run_dns_server():
    # Gradescope tests query 127.0.0.1:53
    DNS_IP = '127.0.0.1'
    DNS_PORT = 53

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((DNS_IP, DNS_PORT))

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire,
                                minimum)
                    rdata_list.append(rdata)
                elif qtype == dns.rdatatype.TXT:
                    # Explicitly handle TXT records by constructing the RDATA object
                    # The answer_data is a tuple of bytes (including the encrypted token)
                    # The TXT constructor takes a list/tuple of byte strings.
                    rdata_list.append(TXT(dns.rdataclass.IN, dns.rdatatype.TXT, answer_data))
                else:
                    # Handle A, AAAA, CNAME, NS using from_text
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                # Add all generated rdata to the response
                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # Set the AA (Authoritative Answer) flag manually
            response.flags |= dns.flags.AA

            # Send the response back to the client
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print(f"DNS server is running on 127.0.0.1:53...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()