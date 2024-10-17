from flask import Flask, render_template, request, jsonify
import socket
import json
from nacl.public import PrivateKey, PublicKey
from nacl.signing import VerifyKey
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from nacl.utils import random
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization

from Alice import *
app = Flask(__name__)

# Global variables
ik_A_private = PrivateKey.generate()
ik_A_public = ik_A_private.public_key
ek_A_private = PrivateKey.generate()
ek_A_public = ek_A_private.public_key

share_SK = None
share_AD = None
share_SPKB = None
private_key = ik_A_private

# Server connection details
SERVER_HOST = 'localhost'
SERVER_PORT = 65432

# Message history
message_history = []
initial_message_sent = False

# Double Ratchet participant
alice = None

@app.route('/')
def index():
    return render_template('alice.html', messages=message_history, show_input=initial_message_sent)

@app.route('/send_message', methods=['POST'])
def send_message():
    global initial_message_sent, alice, share_SK, share_AD, share_SPKB
    message = request.form['message']
    
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        if not initial_message_sent:
            # Send initial message
            prekey_bundle = request_prekey_bundle(client_socket)
            if not prekey_bundle:
                return jsonify({"status": "error", "message": "Failed to get Bob's prekey bundle"})

            shared_secret, opk_id = compute_shared_secret(prekey_bundle)
            if not shared_secret:
                return jsonify({"status": "error", "message": "Failed to compute shared secret"})

            share_SK = shared_secret
            share_SPKB = PublicKey(prekey_bundle["spk_B_public"], encoder=HexEncoder)
            share_AD = ik_A_public.encode() + PublicKey(prekey_bundle["ik_B_public"], encoder=HexEncoder).encode()

            ciphertext = construct_initial_message(shared_secret, prekey_bundle, opk_id, message)
            if not ciphertext:
                return jsonify({"status": "error", "message": "Failed to construct the message"})

            server_response = send_initial_message(client_socket, ciphertext)
            print
            if not server_response:
                return jsonify({"status": "error", "message": "Failed to send the message"})

            # Initialize Double Ratchet
            alice_state = RatchetState(
                RK=share_SK,
                DHs=GENERATE_DH(),
                DHr=convert_SPKB(share_SPKB),
                CKs=None,
                CKr=None,
                Ns=0,
                Nr=0,
                PN=0,
                MKSKIPPED={}
            )
            alice = DoubleRatchetParticipant("Alice", share_SK, share_AD)
            alice.state = alice_state

            initial_message_sent = True
        else:
            # Use Double Ratchet for subsequent messages
            plaintext = message.encode()
            header, ciphertext = alice.ratchet_encrypt(plaintext)

            # Serialize the message for sending
            serialized_message = {
                'header': serialize_header(header),
                'ciphertext': ciphertext.hex()
            }

            send_double_ratchet_message(client_socket, serialized_message)

    message_history.append({"sender": "Alice", "message": message})
    return jsonify({"status": "success", "message": "Message sent successfully"})

@app.route('/check_messages')
def check_messages():
    global alice
    messages = request_message_from_server()
    if not messages:
        return jsonify({"status": "info", "message": "No new messages"})

    new_messages = []
    for message in messages:
        if alice:
            # Use Double Ratchet to decrypt
            header = deserialize_header(message['header'])
            ciphertext = bytes.fromhex(message['ciphertext'])
            plaintext = alice.ratchet_decrypt(header, ciphertext)
            new_message = {"sender": "Bob", "message": plaintext.decode('utf-8')}
            message_history.append(new_message)
            new_messages.append(new_message)

    return jsonify({"status": "success", "messages": new_messages})

# Helper functions (request_prekey_bundle, compute_shared_secret, encrypt_message, construct_initial_message, send_initial_message)
# ... (Copy these functions from the original Alice.py file)

# New helper functions for Double Ratchet
def convert_SPKB(public_key):
    public_key_bytes = public_key.encode()
    x25519_public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
    return x25519_public_key

def serialize_header(header):
    return {
        'dh': header.dh.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        'pn': header.pn,
        'n': header.n
    }

def deserialize_header(header_dict):
    dh_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(header_dict['dh']))
    return Header(dh_pub, header_dict['pn'], header_dict['n'])

def send_double_ratchet_message(client_socket, message):
    request = json.dumps({
        "action": "send_message",
        "user_id": "Bob",
        "message": message
    })
    client_socket.sendall(request.encode('utf-8'))
    response = client_socket.recv(4096).decode('utf-8')
    return json.loads(response)

def request_message_from_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        request = json.dumps({
            "action": "get_messages",
            "user_id": "Alice"
        })
        client_socket.sendall(request.encode('utf-8'))
        response = client_socket.recv(4096).decode('utf-8')
        response = json.loads(response)
        if response["status"] == "success":
            return response["messages"]
    return None

if __name__ == '__main__':
    app.run(port=5000, debug=True)
