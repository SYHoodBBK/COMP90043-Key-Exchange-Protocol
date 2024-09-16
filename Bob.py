# Bob.py

import socket
import threading
from functions import *
from cryptography.hazmat.primitives import serialization

# Predefined parameters from X3DH
SK = b'shared_secret_key_from_X3DH'
AD = b'associated_data_from_X3DH'

# Bob's initial ratchet key pair (SPKB)
bob_initial_DH = GENERATE_DH()  # Bob's initial DH key pair

# Serialize Bob's initial DH public key to send to Alice
bob_initial_DH_pub_bytes = bob_initial_DH.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)


class RatchetState:
    def __init__(self, RK, DHs, DHr, CKs, CKr, Ns, Nr, PN, MKSKIPPED):
        self.RK = RK  # Root key
        self.DHs = DHs  # Our DH key pair (private key)
        self.DHr = DHr  # Their DH public key
        self.CKs = CKs  # Sending chain key
        self.CKr = CKr  # Receiving chain key
        self.Ns = Ns  # Message number in sending chain
        self.Nr = Nr  # Message number in receiving chain
        self.PN = PN  # Number of messages in previous sending chain
        self.MKSKIPPED = MKSKIPPED  # Skipped message keys for out-of-order messages
        self.need_send_ratchet = False  # Flag indicating if send ratchet is needed


# Initialize Bob's state
bob_state = RatchetState(
    RK=SK,
    DHs=bob_initial_DH,  # Bob's initial DH key pair
    DHr=None,  # Bob hasn't received Alice's DH yet
    CKs=None,
    CKr=None,
    Ns=0,
    Nr=0,
    PN=0,
    MKSKIPPED={}
)


def ratchet_encrypt(state, plaintext):
    # Check if we need to perform a send ratchet step
    if state.need_send_ratchet:
        # Perform send ratchet step
        state.PN = state.Ns
        state.Ns = 0
        state.CKs = None
        state.DHs = GENERATE_DH()
        dh_out = DH(state.DHs, state.DHr)
        state.RK, state.CKs = KDF_RK(state.RK, dh_out)
        state.need_send_ratchet = False  # Reset the flag

    # Derive message key
    if state.CKs is None:
        # Initialize CKs if needed (e.g., on first message)
        dh_out = DH(state.DHs, state.DHr)
        state.RK, state.CKs = KDF_RK(state.RK, dh_out)

    state.CKs, mk = KDF_CK(state.CKs)
    # Create header
    header = HEADER(state.DHs, state.PN, state.Ns)

    # Encrypt message
    ad = CONCAT(AD, header)
    ciphertext = ENCRYPT(mk, plaintext, ad)

    # Update state
    state.Ns += 1

    # Return header and ciphertext
    return header, ciphertext


def ratchet_decrypt(state, header, ciphertext):
    # Compare DH public keys
    if state.DHr is None or header.dh.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw) != state.DHr.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw):
        # Perform a receive ratchet step
        state.need_send_ratchet = True  # Indicate that a send ratchet is needed
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.CKr = None
        state.DHr = header.dh
        dh_out = DH(state.DHs, state.DHr)
        state.RK, state.CKr = KDF_RK(state.RK, dh_out)
        print('Bob performed a receive ratchet step')

    # Derive message key
    if state.CKr is None:
        # Initialize CKr if needed
        dh_out = DH(state.DHs, state.DHr)
        state.RK, state.CKr = KDF_RK(state.RK, dh_out)

    state.CKr, mk = KDF_CK(state.CKr)
    # Decrypt message
    ad = CONCAT(AD, header)
    plaintext = DECRYPT(mk, ciphertext, ad)

    # Update state
    state.Nr += 1

    return plaintext


def handle_receive(conn):
    while True:
        try:
            # First, receive the header length
            header_length_bytes = conn.recv(4)
            if not header_length_bytes:
                break
            header_length = int.from_bytes(header_length_bytes, 'big')

            # Then receive the header
            header_bytes = conn.recv(header_length)

            # Deserialize the header
            dh_pub_bytes = header_bytes[:32]
            pn_bytes = header_bytes[32:36]
            n_bytes = header_bytes[36:40]
            dh_pub = x25519.X25519PublicKey.from_public_bytes(dh_pub_bytes)
            pn = int.from_bytes(pn_bytes, 'big')
            n = int.from_bytes(n_bytes, 'big')
            header = Header(dh_pub, pn, n)

            # Now receive the ciphertext length
            ciphertext_length_bytes = conn.recv(4)
            if not ciphertext_length_bytes:
                break
            ciphertext_length = int.from_bytes(ciphertext_length_bytes, 'big')

            # Now receive the ciphertext
            ciphertext = b''
            while len(ciphertext) < ciphertext_length:
                chunk = conn.recv(ciphertext_length - len(ciphertext))
                if not chunk:
                    break
                ciphertext += chunk

            # Decrypt the message
            plaintext = ratchet_decrypt(bob_state, header, ciphertext)
            print('Bob received:', plaintext.decode())

        except Exception as e:
            print('Receive error:', e)
            break


def send_messages(conn):
    while True:
        message = input('Bob: ')
        if message == '':
            continue
        plaintext = message.encode()
        header, ciphertext = ratchet_encrypt(bob_state, plaintext)

        # Serialize the header
        header_bytes = serialize_header(header)
        header_length = len(header_bytes).to_bytes(4, 'big')

        # Prepare the ciphertext length
        ciphertext_length = len(ciphertext).to_bytes(4, 'big')

        # Send header length, header, ciphertext length, ciphertext
        conn.sendall(header_length + header_bytes +
                     ciphertext_length + ciphertext)


if __name__ == '__main__':
    HOST = 'localhost'
    PORT = 65432

    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print('Bob is listening...')
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            # Send Bob's initial DH public key to Alice
            conn.sendall(len(bob_initial_DH_pub_bytes).to_bytes(
                4, 'big') + bob_initial_DH_pub_bytes)

            # Start a thread to handle receiving messages
            threading.Thread(target=handle_receive, args=(conn,)).start()

            # Now send messages
            send_messages(conn)
