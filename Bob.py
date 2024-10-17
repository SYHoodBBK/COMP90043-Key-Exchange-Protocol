import signal
import sys
import os
import socket
import json
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization




share_SK = None
share_AD = None
share_SPKA = None
private_key = None


def generate_and_save_keys():
    global share_SK, share_AD, share_SPKA, private_key
    # Generate Bob's identity key
    ik_B_private = SigningKey.generate()
    
    ik_B_public = ik_B_private.verify_key

    # Generate Bob's signed prekey
    spk_B_private = PrivateKey.generate()
    private_key = spk_B_private
    spk_B_public = spk_B_private.public_key

    # Sign the signed prekey
    signature_B = ik_B_private.sign(spk_B_public.encode())

    # Generate a set of one-time prekeys
    opk_B_private = [PrivateKey.generate() for _ in range(3)]
    opk_B_public = [opk.public_key for opk in opk_B_private]



    return ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public

# load Bob's keys from a file
def load_keys():
    global share_SK, share_AD, share_SPKB, private_key

    return generate_and_save_keys()
    
ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public = load_keys()


# Save Bob's identity key and prekeys bundle
bob_prekey_bundle = {
    "identity_key": ik_B_public.encode().hex(),
    "signed_prekey": spk_B_public.encode().hex(),
    "signature": signature_B.signature.hex(),
    "one_time_prekeys": [opk.encode().hex() for opk in opk_B_public]
}



def send_prekey_bundle_to_server():
    server_host = 'localhost'
    server_port = 65432

    # Create a socket connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((server_host, server_port))
        print(f"Connected to server at {server_host}:{server_port}")

        # check if the server already has Bob's keys
        request = json.dumps({
            "action": "get_key",
            "user_id": "Bob",
        })

        client_socket.sendall(request.encode('utf-8'))

        # Receive the response
        server_response = client_socket.recv(4096).decode('utf-8')
        server_response = json.loads(server_response)

        if server_response["status"] == "success" and server_response["prekey_bundle"]:
            print("Bob's keys already registered with the server")
            print(f"Bob's prekey bundle: {server_response['prekey_bundle']}")
        else:
            # Send the prekey bundle to the server
            request = json.dumps({
                "action": "register",
                "user_id": "Bob",
                **bob_prekey_bundle
            })
            client_socket.sendall(request.encode('utf-8'))
            print("Sent prekey bundle to server")

            # Receive the response
            server_response = client_socket.recv(1024).decode('utf-8')
            print(f"Received response: {server_response}")
        
        close_message = json.dumps({
            "action": "disconnect"
        })

        client_socket.sendall(close_message.encode('utf-8'))
        print("Sent disconnect message to server")
    except Exception as e:
        print(f"Error sending prekey bundle to server: {e}")
    finally:
        client_socket.close()

def request_message_from_server():
    server_host = 'localhost'
    server_port = 65432

    # Create a socket connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((server_host, server_port))
        print(f"Connected to server at {server_host}:{server_port}")

        request = json.dumps({
            "action": "get_messages",
            "user_id": "Bob"
        })

        client_socket.sendall(request.encode('utf-8'))

        # Receive the response
        server_response = client_socket.recv(4096).decode('utf-8')
        server_response = json.loads(server_response)
        print(f"Received response: {server_response}")

        if server_response["status"] == "success":
            messages = server_response["messages"]
            if messages:
                # print(f"Messages received: {messages}")
                return messages
            else:
                print("No new messages")
        else:
            print(f"Error: {server_response['message']}")
            
    except Exception as e:
        print(f"Error requesting message from server: {e}")
    finally:
        client_socket.close()

# compute the shared secret
def compute_shared_secret(message):
    # Extract the message components
    ik_A_public = message["ik_A_public"]
    ek_A_public = message["ek_A_public"]
    opk_B_public_id = message["opk_B_public_id"]
    nonce = message["nonce"]
    ciphertext = message["ciphertext"]

    # Covert Alice's public keys to the appropriate format
    ik_A_public = PublicKey(ik_A_public, encoder=HexEncoder)
    ek_A_public = PublicKey(ek_A_public, encoder=HexEncoder)

    # Convert Bob's private keys to the appropriate format
    # ik_B_private = PrivateKey(ik_B_private, encoder=HexEncoder)

    # print(f"ik_A_public: {ik_A_public.encode().hex()}")
    # print(f"ek_A_public: {ek_A_public.encode().hex()}")
    # print(f"ik_B_private: {ik_B_private.encode().hex()}")
    # print(f"spk_B_private: {spk_B_private.encode().hex()}")


    # compute the Diffie-Hellman values and combine them
    dh1 = Box(spk_B_private, ik_A_public).shared_key()
    dh2 = Box(ik_B_private.to_curve25519_private_key(), ek_A_public).shared_key()
    dh3 = Box(spk_B_private, ek_A_public).shared_key()

    dh_values = dh1 + dh2 + dh3

    if opk_B_public_id is not None and opk_B_private is not None:
        # Find the one-time prekey used by Alice
        opk_B = opk_B_private[opk_B_public_id]
        print("opk_B:", opk_B.encode().hex())
        dh4 = Box(opk_B, ek_A_public).shared_key()
        dh_values += dh4

    # Derive the shared secret
    shared_secret = sha256(dh_values, encoder=HexEncoder)
    shared_secret_bytes = bytes.fromhex(shared_secret.decode())

    print("Shared secret:", shared_secret.hex())
    print("Shared secret computed")


    return shared_secret_bytes

def decrypt_message(message):
    global share_SK, share_AD, share_SPKA, private_key
    # Extract the message components
    nonce = bytes.fromhex(message["nonce"])
    ciphertext = bytes.fromhex(message["ciphertext"])
    ik_A_public_hex = message["ik_A_public"]
    ik_A_public = PublicKey(ik_A_public_hex, encoder=HexEncoder)

    # Calculate the additional data
    ad = ik_A_public.encode() + ik_B_public.encode()

    share_AD = ad
    share_SPKA = ik_A_public

    # Create a ChaCha20Poly1305 cipher using the shared secret
    cipher = ChaCha20Poly1305(shared_secret)

    # Decrypt the message
    decrypted_message = cipher.decrypt(nonce, ciphertext, ad)
    print("Decrypted message:", decrypted_message.decode('utf-8'))

    return decrypted_message

def convert_private_key(private_key):
    # private_key is generate by SigningKey.generate()
    # need to convert to x25519.X25519PrivateKey.generate()
    private_key_bytes = private_key.encode()
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(
        private_key_bytes)
    print("Bob的私钥:", x25519_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex())

    print("Bob的公钥:", x25519_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex())

    return x25519_private_key

def convert_SPKA(public_key):
    # public_key is generate by PublicKey(ik_A_public_hex, encoder=HexEncoder)
    # need to convert to x25519.X25519PublicKey
    public_key_bytes = public_key.encode()
    x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
        public_key_bytes)
    return x25519_public_key

def doubleRatchet():
    global share_SK, share_AD, share_SPKA, private_key

    bob_state = RatchetState(
        RK=share_SK,
        DHs=convert_private_key(private_key),  # Bob's initial DH key pair
        DHr=convert_SPKA(share_SPKA),  # Bob hasn't received Alice's DH yet
        CKs=None,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        MKSKIPPED={}
    )

    
    bob = DoubleRatchetParticipant("Bob", share_SK, share_AD)
    bob.state = bob_state

    HOST = 'localhost'
    PORT = 23456
    # Create a socket
    import socket



    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print('Bob is listening...')
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                # Start communication
                bob.start_communication(conn)
    except KeyboardInterrupt:
        print('Server interrupted by user')
    finally:
        print('Server shutting down...')
        s.close()
        sys.exit(0)




if __name__ == '__main__':
    # Generate or load Bob's keys
    

    send_prekey_bundle_to_server()
    while True:
        user_input = input("Enter 'get' to retrieve messages or 'exit' to quit: ")
        if user_input.lower() == 'get':
            messages = request_message_from_server()
            if messages:
                print(f"Messages received: {messages}")
                shared_secret = compute_shared_secret(messages[0])
                if shared_secret:
                    share_SK = shared_secret
                    decrypted_message = decrypt_message(messages[0])

                    doubleRatchet()
        elif user_input.lower() == 'exit':
            print("Exiting Bob.")
            break
    # request_message_from_server()