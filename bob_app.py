from flask import Flask, render_template, jsonify, request
import socket
import json
import threading
import time
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization

from Bob import *

app = Flask(__name__)

# Global variables
ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public = generate_and_save_keys()
share_SK = None
share_AD = None
share_SPKA = None
private_key = None

# Server connection details
SERVER_HOST = 'localhost'
SERVER_PORT = 65432

# Message history
message_history = []
initial_message_received = False

# Double Ratchet participant
bob = None

def register_and_check_messages():
    global initial_message_received, share_SK, share_AD, share_SPKA, private_key, bob
    send_prekey_bundle_to_server()
    print("Keys registered successfully")
    
    while not initial_message_received:
        messages = request_message_from_server()
        if messages:
            for message in messages:
                shared_secret = compute_shared_secret(message)
                if shared_secret:
                    share_SK = shared_secret
                    decrypted_message = decrypt_message(message)
                    message_history.append({"sender": "Alice", "message": decrypted_message.decode('utf-8')})
                    initial_message_received = True
                    print("Initial message received from Alice")

                    # Initialize Double Ratchet
                    bob_state = RatchetState(
                        RK=share_SK,
                        DHs=convert_private_key(private_key),
                        DHr=convert_SPKA(share_SPKA),
                        CKs=None,
                        CKr=None,
                        Ns=0,
                        Nr=0,
                        PN=0,
                        MKSKIPPED={}
                    )
                    bob = DoubleRatchetParticipant("Bob", share_SK, share_AD)
                    bob.state = bob_state

        time.sleep(5)  # Wait for 5 seconds before checking again

# Start the background thread
threading.Thread(target=register_and_check_messages, daemon=True).start()

@app.route('/')
def index():
    return render_template('bob.html', messages=message_history, show_input=initial_message_received)

@app.route('/check_messages')
def check_messages():
    global initial_message_received, bob
    messages = request_message_from_server()
    if not messages:
        return jsonify({"status": "info", "message": "No new messages", "show_input": initial_message_received})

    new_messages = []
    for message in messages:
        if not initial_message_received:
            shared_secret = compute_shared_secret(message)
            if shared_secret:
                decrypted_message = decrypt_message(message)
                new_message = {"sender": "Alice", "message": decrypted_message.decode('utf-8')}
        else:
            # Use Double Ratchet to decrypt
            header = deserialize_header(message['header'])
            ciphertext = bytes.fromhex(message['ciphertext'])
            plaintext = bob.ratchet_decrypt(header, ciphertext)
            new_message = {"sender": "Alice", "message": plaintext.decode('utf-8')}

        message_history.append(new_message)
        new_messages.append(new_message)
        initial_message_received = True

    return jsonify({"status": "success", "messages": new_messages, "show_input": initial_message_received})

@app.route('/send_message', methods=['POST'])
def send_message():
    global bob
    message = request.form['message']
    
    if not bob:
        return jsonify({"status": "error", "message": "Double Ratchet not initialized"})

    plaintext = message.encode()
    header, ciphertext = bob.ratchet_encrypt(plaintext)

    # Serialize the message for sending
    serialized_message = {
        'header': serialize_header(header),
        'ciphertext': ciphertext.hex()
    }

    # Send the message to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        send_double_ratchet_message(client_socket, serialized_message)

    message_history.append({"sender": "Bob", "message": message})
    return jsonify({"status": "success", "message": "Message sent successfully"})

# Helper functions (generate_and_save_keys, send_prekey_bundle_to_server, request_message_from_server, compute_shared_secret, decrypt_message, etc.)
# ... (Copy these functions from the original Bob.py file)

# New helper functions for Double Ratchet
def convert_private_key(private_key):
    private_key_bytes = private_key.encode()
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    return x25519_private_key

def convert_SPKA(public_key):
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
        "user_id": "Alice",
        "message": message
    })
    client_socket.sendall(request.encode('utf-8'))
    response = client_socket.recv(4096).decode('utf-8')
    return json.loads(response)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
