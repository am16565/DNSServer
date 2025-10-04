import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdata
import dns.rrset
import dns.flags

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


# Lookup details on fernet in the cryptography.io documentation
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # call the Fernet encrypt method
    return encrypted_data


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)  # call the Fernet decrypt method
    return decrypted_data.decode('utf-8')


salt = b"Tandon"  # Remember it should be a byte-object
password = "sm13733@nyu.edu"  # <<-- REPLACE with your NYU email used for Gradescope
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function


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
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
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

    # Example of adding nyu.edu with the encrypted TXT from above (you can add the assignment records similarly)
    'nyu.edu.': {
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),  # store encrypted value as string in TXT
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: ('2001:0db8:85a3:0000:0000:8a2e:0373:7312',),
        dns.rdatatype.NS: ('ns1.nyu.edu.',),
    }

    # Add more records as needed (see assignment instructions)
}


def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port (the standard port for DNS is 53)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    BIND_IP = "127.0.0.1"
    PORT = 53  # change to e.g., 5053 if you can't run as root
    try:
        server_socket.bind((BIND_IP, PORT))
    except PermissionError:
        print(f"Permission denied binding to {BIND_IP}:{PORT}. Run as root or change PORT to >1023 for testing.")
        return
    except Exception as e:
        print("Bind failed:", e)
        return

    print(f"DNS server bound to {BIND_IP}:{PORT} (UDP)")

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(4096)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name
            qname_text = qname.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname_text in dns_records and qtype in dns_records[qname_text]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname_text][qtype]

                rdata_list = []

                # Handle MX specially (we stored as list of tuples)
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        # use from_text to build the rdata safely
                        rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, f"{pref} {server}"))

                # Handle SOA specially
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    soa_text = f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                    rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, soa_text))

                else:
                    # Generic handling:
                    # If answer_data is a single string for single-record types, convert to list
                    if isinstance(answer_data, str):
                        data_items = [answer_data]
                    else:
                        data_items = list(answer_data)

                    # Special-case TXT: ensure each TXT string is quoted (from_text wants quotes)
                    if qtype == dns.rdatatype.TXT:
                        for data_item in data_items:
                            # If data_item contains double quotes already, don't double-quote
                            if data_item.startswith('"') and data_item.endswith('"'):
                                txt_text = data_item
                            else:
                                txt_text = f'"{data_item}"'
                            rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txt_text))
                    else:
                        for data_item in data_items:
                            rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, qtype, data_item))

                # Attach answer rrsets to the response
                for rdata in rdata_list:
                    rr = dns.rrset.RRset(qname, dns.rdataclass.IN, qtype)
                    rr.add(rdata)
                    response.answer.append(rr)

            else:
                # name not found -> NXDOMAIN
                response.set_rcode(dns.rcode.NXDOMAIN)

            # Set the Authoritative Answer flag (AA)
            response.flags |= dns.flags.AA

            # Send the response back to the client
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname_text, "type:", dns.rdatatype.to_text(qtype), "->", addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print("Error handling request:", e)
            # keep running for other requests


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

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
    # print("Encrypted Value:", encrypted_value)
    # print("Decrypted Value:", decrypted_value)