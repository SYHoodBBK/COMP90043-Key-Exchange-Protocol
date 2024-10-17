import asyncio
import websockets
import json
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from nacl.utils import random
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptography.hazmat.primitives.asymmetric import x25519

# Generate Alice's identity key pair
ik_A_private = PrivateKey.generate()
ik_A_public = ik_A_private.public_key

# Generate Alice's ephemeral key pair
ek_A_private = PrivateKey.generate()
ek_A_public = ek_A_private.public_key

# Define the server host and port
server_host = 'localhost'
server_port = 23456

share_SK = None
share_AD = None
share_SPKB = None
private_key = ik_A_private

async def request_prekey_bundle(websocket):
    try:
        # Send the request to the server
        request = json.dumps({
            "action": "get_key",
            "user_id": "Bob"
        })
        await websocket.send(request)
        print("Sent request to server")

        # Receive the response
        response = await websocket.recv()
        response = json.loads(response)
        print(f"Received response: {response}")
        if response["status"] == "success":
            return response["prekey_bundle"]
        else:
            print(f"Error: {response['message']}")
            return None

    except Exception as e:
        print(f"Error requesting prekey bundle: {e}")
        return None

# Process Bob's prekey bundle
def compute_shared_secret(prekey_bundle):
    global share_SPKB
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
    global share_SK, share_AD
    try:
        # ChaCha20-Poly1305 expects a 32-byte key (256-bit)
        if len(shared_secret) != 32:
            print(f'len(shared_key): {len(shared_secret)}')
            raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")
        
        share_SK = shared_secret
        share_AD = ad
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
def construct_initial_message(shared_secret, prekey_bundle, opk_id):
    try:
        # Construct the initial message
        message = "Hello, Bob!"
        ik_B_public_hex = prekey_bundle["ik_B_public"]
        ik_B_public = PublicKey(ik_B_public_hex, encoder=HexEncoder)
        ad = ik_A_public.encode() + ik_B_public.encode()
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

async def send_initial_message(websocket, initial_message):
    try:
        message_data = {
            "action": "send_message",
            "user_id": "Bob",
            "message": initial_message
        }

        message_data = json.dumps(message_data)
        await websocket.send(message_data)
        print("Sent initial message to Server...")

        # Receive the response
        server_response = await websocket.recv()
        server_response = json.loads(server_response)
        print(f"Received response: {server_response}")

        return server_response
    except Exception as e:
        print(f"Error sending initial message: {e}")
        return None

async def main():
    uri = f"ws://{server_host}:{server_port}"
    async with websockets.connect(uri) as websocket:
        print(f"Connected to server at {uri}")

        # Request Bob's prekey bundle from the server
        prekey_bundle = await request_prekey_bundle(websocket)
        if prekey_bundle:
            # Compute the shared secret with Bob
            shared_secret, opk_id = compute_shared_secret(prekey_bundle)
            if shared_secret:
                # Construct the initial message
                ciphertext = construct_initial_message(shared_secret, prekey_bundle, opk_id)
                if ciphertext:
                    # Send the initial message to Bob
                    server_response = await send_initial_message(websocket, ciphertext)
                    if server_response:
                        print("Alice's initial message sent to Bob")

async def get_alice_info():
    
    uri = f"ws://{server_host}:{server_port}"
    async with websockets.connect(uri) as websocket:
        print(f"Connected to server at {uri}")

        # Request Bob's prekey bundle from the server
        prekey_bundle = await request_prekey_bundle(websocket)
        if prekey_bundle:
            # Compute the shared secret with Bob
            shared_secret, opk_id = compute_shared_secret(prekey_bundle)
            if shared_secret:
                # Construct the initial message
                ciphertext = construct_initial_message(
                    shared_secret, prekey_bundle, opk_id)
                if ciphertext:
                    # Send the initial message to Bob
                    server_response = await send_initial_message(websocket, ciphertext)
                    if server_response:
                        print("Alice's initial message sent to Bob")
    # private_key is generate by PrivateKey.generate()
    # need to convert to x25519.X25519PrivateKey.generate()
    private_key_bytes = private_key.encode()
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(
        private_key_bytes)
    
    # SPKB is generate by PublicKey(ik_A_public_hex, encoder=HexEncoder)
    # need to convert to x25519.X25519PublicKey
    spkb = share_SPKB.encode()
    x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
        spkb)
    
    return share_SK, share_AD, x25519_public_key, x25519_private_key


if __name__ == "__main__":
    asyncio.run(main())
