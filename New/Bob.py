import os
import socket
import json
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Key files
KEY_FILE = 'New/bob_keys.json'
keys_store = {}

def generate_and_save_keys():
    # Generate Bob's identity key
    ik_B_private = SigningKey.generate()
    ik_B_public = ik_B_private.verify_key

    # Generate Bob's signed prekey
    spk_B_private = PrivateKey.generate()
    spk_B_public = spk_B_private.public_key

    # Sign the signed prekey
    signature_B = ik_B_private.sign(spk_B_public.encode())

    # Generate a set of one-time prekeys
    opk_B_private = [PrivateKey.generate() for _ in range(3)]
    opk_B_public = [opk.public_key for opk in opk_B_private]

    # Save Bob's keys to a file
    with open(KEY_FILE, 'w') as key_file:
        key_data = {
            "ik_B_private": ik_B_private.encode().hex(),
            "ik_B_public": ik_B_public.encode().hex(),
            "spk_B_private": spk_B_private.encode().hex(),
            "spk_B_public": spk_B_public.encode().hex(),
            "signature_B": signature_B.signature.hex(),
            "opk_B_private": [opk.encode().hex() for opk in opk_B_private],
            "opk_B_public": [opk.encode().hex() for opk in opk_B_public]
        }
        json.dump(key_data, key_file)

    return ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public

# load Bob's keys from a file
def load_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as key_file:
            key_data = json.load(key_file)
            ik_B_private = SigningKey(bytes.fromhex(key_data["ik_B_private"]))
            ik_B_public = VerifyKey(bytes.fromhex(key_data["ik_B_public"]))
            spk_B_private = PrivateKey(bytes.fromhex(key_data["spk_B_private"]))
            spk_B_public = PrivateKey(bytes.fromhex(key_data["spk_B_public"]))
            signature_B = ik_B_private.sign(spk_B_public.encode())
            opk_B_private = [PrivateKey(bytes.fromhex(k)) for k in key_data["opk_B_private"]]
            opk_B_public = [PrivateKey(bytes.fromhex(k)).public_key for k in key_data["opk_B_public"]]

            return ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public
    else:
        return generate_and_save_keys()
    
# Generate or load Bob's keys
ik_B_private, ik_B_public, spk_B_private, spk_B_public, signature_B, opk_B_private, opk_B_public = load_keys()


# Output the results
# print("Bob's identity key (IK_B):", ik_B_private.encode().hex())
# print("Bob's signed prekey (SPK_B):", spk_B_private.encode().hex())
# print("Signature (Sig(IK_B, Encode(SPK_B))):", signature_B.signature.hex())

# for i, opk in enumerate(opk_B_private, start=1):
#     print(f"Bob's one-time prekey OPK_B{i}:", opk.encode().hex())

# Save Bob's identity key and prekeys bundle
bob_prekey_bundle = {
    "identity_key": ik_B_public.encode().hex(),
    "signed_prekey": spk_B_public.encode().hex(),
    "signature": signature_B.signature.hex(),
    "one_time_prekeys": [opk.encode().hex() for opk in opk_B_public]
}

# Output the bundle
# print('Bob\'s Identity Key:', bob_prekey_bundle['identity_key'])
# print('Bob\'s Signed Prekey:', bob_prekey_bundle['signed_prekey'])
# print('Bob\'s Signature:', bob_prekey_bundle['signature'])
# print('Bob\'s One-time Prekeys:', bob_prekey_bundle['one_time_prekeys'])

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

    print(f"ik_A_public: {ik_A_public.encode().hex()}")
    print(f"ek_A_public: {ek_A_public.encode().hex()}")
    print(f"ik_B_private: {ik_B_private.encode().hex()}")
    print(f"spk_B_private: {spk_B_private.encode().hex()}")


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

if __name__ == '__main__':
    send_prekey_bundle_to_server()
    while True:
        user_input = input("Enter 'get' to retrieve messages or 'exit' to quit: ")
        if user_input.lower() == 'get':
            messages = request_message_from_server()  # 获取消息
            if messages:
                print(f"Messages received: {messages}")
                compute_shared_secret(messages[0])
        elif user_input.lower() == 'exit':
            print("Exiting Bob.")
            break
    # request_message_from_server()