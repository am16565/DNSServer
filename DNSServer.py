import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
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
from typing import Tuple, List, Dict, Any


# --- Cryptography Functions ---

def generate_aes_key(password: str, salt: bytes) -> bytes:
    """Generates a Fernet key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    # Fernet keys must be 32 url-safe base64-encoded bytes
    key = base64.urlsafe_b64encode(key)
    return key


def encrypt_with_aes(input_string: str, password: str, salt: bytes) -> bytes:
    """Encrypts a string using a Fernet key derived from password and salt."""
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # call the Fernet encrypt method
    return encrypted_data


def decrypt_with_aes(encrypted_data: bytes, password: str, salt: bytes) -> str:
    """Decrypts bytes using a Fernet key derived from password and salt."""
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)  # call the Fernet decrypt method
    return decrypted_data.decode('utf-8')


# --- Cryptography Execution ---

salt = os.urandom(16)  # Remember it should be a byte-object, 16 bytes is standard for salt
password = "supersecretpassword"
input_string = "This is the data to be exfiltrated or encrypted."

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function


# --- Utility Function ---

def generate_sha256_hash(input_string: str) -> str:
    """Generates the SHA256 hash of an input string."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


# --- DNS Server Setup ---

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records: Dict[str, Dict[dns.rdatatype.RdataType, Any]] = {
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
    'subdomain.example.com.': {  # Added an extra record for completeness
        dns.rdatatype.A: '192.168.1.102',
    }
}


def run_dns_server():
    # Create a UDP socket and bind it to the local IP address (0.0.0.0 for all interfaces) and port (53 for DNS)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # SOCK_DGRAM for UDP
    server_socket.bind(('0.0.0.0', 53))  # Bind to all interfaces on the standard DNS port

    print(f"DNS server listening on 0.0.0.0:53...")

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the question from the request
            # A DNS request can have multiple questions, but for simplicity, we process the first one (index 0).
            if not request.question:
                continue

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        # MX(rdclass, rdtype, preference, exchange)
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, dns.name.from_text(server)))
                elif qtype == dns.rdatatype.SOA:
                    # Record format: (mname, rname, serial, refresh, retry, expire, minimum)
                    (mname, rname, serial, refresh, retry, expire, minimum) = answer_data
                    rdata = SOA(
                        dns.rdataclass.IN,
                        dns.rdatatype.SOA,
                        dns.name.from_text(mname),  # mname
                        dns.name.from_text(rname),  # rname
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum
                    )
                    rdata_list.append(rdata)
                elif qtype == dns.rdatatype.TXT:
                    # TXT records have their data as a tuple of strings
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{data}"') for data in answer_data]
                else:
                    # Handles A, AAAA, CNAME, NS, and other single-string records
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        # Should not happen for basic records but kept for robustness
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                for rdata in rdata_list:
                    # Create the resource record set
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # Set the response flags: QR (Query Response) is bit 15 (1<<15), but dnspython handles this in make_response.
            # AA (Authoritative Answer) is bit 10. Setting it ensures the server claims authority for the domain.
            response.flags |= dns.flags.AA  # Set the Authoritative Answer flag

            # Send the response back to the client
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            # Catch other exceptions like parsing errors and continue the loop
            print(f"An error occurred: {e}")
            continue


# --- DNS Server User Interface ---

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            try:
                cmd = input()
                if cmd.lower() == 'q':
                    print('Quitting...')
                    # Send SIGINT to the main process to trigger the KeyboardInterrupt in run_dns_server
                    os.kill(os.getpid(), signal.SIGINT)
                    break
            except EOFError:
                # Handle case where input stream is closed
                break
            except Exception:
                # Ignore other input exceptions
                pass

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()

    # Run the main DNS server loop
    run_dns_server()


if __name__ == '__main__':
    # Print crypto results for testing/debugging
    print("\n--- Cryptography Test ---")
    print("Input String:", input_string)
    print("Encrypted Value (Base64 URL-safe bytes):", encrypted_value)
    print("Decrypted Value (String):", decrypted_value)
    print("-------------------------\n")

    run_dns_server_user()