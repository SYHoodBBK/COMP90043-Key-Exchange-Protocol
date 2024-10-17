import socket
import json
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from nacl.utils import random
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization


share_SK = None
share_AD = None
share_SPKB = None
private_key = None

# Connect to the server to request Bob's prekey bundle
def request_prekey_bundle(client_socket):
    try:
        # Send the request to the server
        request = json.dumps({
            "action": "get_key",
            "user_id": "Bob"
        })
        client_socket.sendall(request.encode('utf-8'))
        print("Sent request to server")

        # Receive the response
        response = client_socket.recv(4096).decode('utf-8')
        response = json.loads(response)
        print(f"Received response: {response}")
        if response["status"] == "success":
            return response["prekey_bundle"]
        else:
            print(f"Error: {response['message']}")

        close_message = json.dumps({
            "action": "disconnect"
        })

        client_socket.sendall(close_message.encode('utf-8'))
        print("Sent disconnect message to server")

    except Exception as e:
        print(f"Error requesting prekey bundle: {e}")
    # finally:
    #     client_socket.close()

# Process Bob's prekey bundle
def compute_shared_secret(prekey_bundle):
    global share_SK, share_AD, share_SPKB, private_key
    try:
        # Extract Bob's public keys and signature from the prekey bundle
        ik_B_public_hex = prekey_bundle["ik_B_public"]
        spk_B_public_hex = prekey_bundle["spk_B_public"]
        signature_B_hex = prekey_bundle["signature_B"]
        opk_B_public_hex_list = prekey_bundle["opk_B_public"]

        print("Received Bob's public keys and signature")

        # Convert Bob's public keys and signature to the appropriate format
        ik_B_public = VerifyKey(ik_B_public_hex, encoder=HexEncoder)
        print(f'ik_B_public: {ik_B_public.encode().hex()}')
        spk_B_public = PublicKey(spk_B_public_hex, encoder=HexEncoder)
        signature_B = bytes.fromhex(signature_B_hex)
        print("Bob的公钥: ", ik_B_public.encode().hex())
        share_SPKB = spk_B_public

        # Verify Bob's signed prekey signature
        try:
            # ik_B_verify = VerifyKey(ik_B_public_hex, encoder=HexEncoder)
            print(f'ik_B_verify: {ik_B_public.encode().hex()}')
            ik_B_public.verify(spk_B_public.encode(), signature_B)
            print("Signature verification successful")
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return
        
        # Choose one of Bob's one-time prekeys
        opk_B_public = None
        opk_B_id = None
        if opk_B_public_hex_list:
            opk_B_public_hex = opk_B_public_hex_list[0]
            opk_B_public = PublicKey(opk_B_public_hex, encoder=HexEncoder)
            opk_B_id = 0
            # print("Chose one-time prekey:", opk_B_public_hex)

        print(f'ik_A_private: {ik_A_private.encode().hex()}')
        print(f'ek_A_private: {ek_A_private.encode().hex()}')
        print(f'ik_B_public: {ik_B_public.encode().hex()}')
        print(f'spk_B_public: {spk_B_public.encode().hex()}')


        # compute the Diffie-Hellman values and combine them
        dh1 = Box(ik_A_private, spk_B_public).shared_key()
        dh2 = Box(ek_A_private, ik_B_public.to_curve25519_public_key()).shared_key()
        dh3 = Box(ek_A_private, spk_B_public).shared_key()
        # Compute the shared key by combining the Diffie-Hellman values
        dh_values = dh1 + dh2 + dh3
        if opk_B_public:
            dh4 = Box(ek_A_private, opk_B_public).shared_key()
            print(f'opk_B_public: {opk_B_public.encode().hex()}')
            dh_values += dh4
        # print(f'lenght of dh_values: {len(dh_values)}')
        # Derive the shared secret
        shared_secret = sha256(dh_values, encoder=HexEncoder)
        shared_secret_bytes = bytes.fromhex(shared_secret.decode())
        # print(f'lenght of shared_secret: {len(shared_secret.hex())}')
        print(f"Shared secret: {shared_secret.hex()}")
        print("Shared secret computed successfully")

        # print(f"Ephemeral private key before deletion: {ek_A_private}")

        return shared_secret_bytes, opk_B_id
    except Exception as e:
        print(f"Error computing shared key: {e}")
    # finally:
    #     # Delete the Ephemeral private key
    #     if ek_A_private is not None:
    #         del ek_A_private
    #         print("Deleted Alice's ephemeral private key.")

# Encrypt the initial message
def encrypt_message(shared_secret, ad, message):
    try:
        # ChaCha20-Poly1305 expects a 32-byte key (256-bit)
        if len(shared_secret) != 32:
            print(f'len(shared_key): {len(shared_secret)}')
            raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")
        
        # Generate a random nonce
        nonce = random(12)
        # print(f"Nonce: {nonce.hex()}")
        # print("Nonce generated successfully")

        # # Create a ChaCha20-Poly1305 cipher using the shared key
        cipher = ChaCha20Poly1305(shared_secret)

        # # Encrypt the message
        ciphertext = cipher.encrypt(nonce, message.encode('utf-8'), ad)
        
        # print(f"Ciphertext: {ciphertext.hex()}")
        print("Message encrypted successfully")
        return nonce.hex(), ciphertext.hex()
    
    except Exception as e:
        print(f"Error encrypting message: {e}")

# Construct the initial message
def construct_initial_message(shared_secret, prekey_bundle, opk_id, message):
    global share_SK, share_AD, share_SPKB, private_key
    try:
        # Construct the initial message

        ik_B_public_hex = prekey_bundle["ik_B_public"]
        ik_B_public = PublicKey(ik_B_public_hex, encoder=HexEncoder)
        ad = ik_A_public.encode() + ik_B_public.encode()
        share_AD = ad
        nonce_hex, ciphertext_hex = encrypt_message(shared_secret, ad, message)

        initial_message = {
            "ik_A_public": ik_A_public.encode().hex(),
            "ek_A_public": ek_A_public.encode().hex(),
            "opk_B_public_id": opk_id,
            "nonce": nonce_hex,
            "ciphertext": ciphertext_hex,
        }
        # print("Initial message:", initial_message)
        print("Initial message constructed successfully")
        return initial_message
    except Exception as e:
        print(f"Error constructing initial message: {e}")

# Send the initial message to Bob
def send_initial_message(client_socket, initial_message):
    try:
        message_data = {
            "action": "send_message",
            "user_id": "Bob",
            "message": initial_message
        }

        message_data = json.dumps(message_data)
        client_socket.sendall(message_data.encode('utf-8'))
        print("Sent initial message to Server...")

        # Receive the response
        server_response  = client_socket.recv(4096).decode('utf-8')
        server_response  = json.loads(server_response)
        print(f"Received response: {server_response}")

        close_message = json.dumps({
            "action": "disconnect"
        })

        client_socket.sendall(close_message.encode('utf-8'))
        print("Sent disconnect message to server")

        return server_response
    except Exception as e:
        print(f"Error sending initial message: {e}")
    # finally:
    #     client_socket.close()


def convert_private_key(private_key):
    # private_key is generate by PrivateKey.generate()
    # need to convert to x25519.X25519PrivateKey.generate()
    private_key_bytes = private_key.encode()
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(
        private_key_bytes)
    return x25519_private_key


def convert_SPKB(public_key):
    # public_key is generate by PublicKey(ik_A_public_hex, encoder=HexEncoder)
    # need to convert to x25519.X25519PublicKey
    public_key_bytes = public_key.encode()
    x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
        public_key_bytes)

    return x25519_public_key

def doubleRatchet():
    global share_SK, share_AD, share_SPKB, private_key
    alice_state = RatchetState(
        RK=share_SK,
        DHs=GENERATE_DH(),  # Alice's initial DH key pair
        DHr=convert_SPKB(share_SPKB),  # Bob's initial DH public key
        CKs=None,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        MKSKIPPED={}
    )


    alice = DoubleRatchetParticipant("Alice", share_SK, share_AD)
    alice.state = alice_state

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 23456))
        alice.start_communication(s)

if __name__ == "__main__":

        # Generate Alice's identity key pair
    ik_A_private = PrivateKey.generate()
    ik_A_public = ik_A_private.public_key

    private_key = ik_A_private

    # Generate Alice's ephemeral key pair
    ek_A_private = PrivateKey.generate()
    ek_A_public = ek_A_private.public_key

    # Define the server host and port
    server_host = 'localhost'
    server_port = 65432

    # Create a socket connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    print(f"Connected to server at {server_host}:{server_port}")

    # Request Bob's prekey bundle from the server
    prekey_bundle = request_prekey_bundle(client_socket)
    if prekey_bundle:
        # Compute the shared secret with Bob
        shared_secret, opk_id = compute_shared_secret(prekey_bundle)
        share_SK = shared_secret
        if shared_secret:
            # Construct the initial message
            message = "Hello, Bob!"
            ciphertext = construct_initial_message(shared_secret, prekey_bundle, opk_id, message)
            if ciphertext:
                # Send the initial message to Bob
                server_response = send_initial_message(client_socket, ciphertext)
                if server_response:
                    print("Alice's initial message sent to Bob")
                    while True:
                        user_input = input(
                            "Enter 'send' to start DH messages or 'exit' to quit: ")
                        if user_input.lower() == 'send':
                            doubleRatchet()
                        elif user_input.lower() == 'exit':
                            print("Exiting...")
                            break
                        

