# DoubleRatchetParticipant.py

import asyncio
import websockets
from functions import *
from cryptography.hazmat.primitives import serialization

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

class DoubleRatchetParticipant:
    def __init__(self, name, SK, AD):
        self.name = name
        self.SK = SK
        self.AD = AD
        self.state = None

    def ratchet_encrypt(self, plaintext):
        state = self.state
        ratchet_performed = False
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
            ratchet_performed = True

        # Derive message key
        if state.CKs is None:
            # Initialize CKs if needed (e.g., on first message)
            dh_out = DH(state.DHs, state.DHr)
            state.RK, state.CKs = KDF_RK(state.RK, dh_out)

        state.CKs, mk = KDF_CK(state.CKs)
        # Create header
        header = HEADER(state.DHs, state.PN, state.Ns)

        # Encrypt message
        ad = CONCAT(self.AD, header)
        ciphertext = ENCRYPT(mk, plaintext, ad)

        # Update state
        state.Ns += 1

        # Return header and ciphertext
        return header, ciphertext, ratchet_performed

    def ratchet_decrypt(self, header, ciphertext):
        state = self.state
        ratchet_performed = False
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
            ratchet_performed = True
            print(f'{self.name}: Performing a receive ratchet step')

        # Derive message key
        if state.CKr is None:
            # Initialize CKr if needed
            dh_out = DH(state.DHs, state.DHr)
            state.RK, state.CKr = KDF_RK(state.RK, dh_out)

        state.CKr, mk = KDF_CK(state.CKr)
        # Decrypt message
        ad = CONCAT(self.AD, header)
        plaintext = DECRYPT(mk, ciphertext, ad)

        # Update state
        state.Nr += 1

        return plaintext, ratchet_performed

    async def handle_receive(self, websocket):
        try:
            async for message in websocket:
                # Deserialize the message
                header_length = int.from_bytes(message[:4], 'big')
                header_bytes = message[4:4+header_length]
                ciphertext_length = int.from_bytes(message[4+header_length:8+header_length], 'big')
                ciphertext = message[8+header_length:]

                # Deserialize the header
                dh_pub_bytes = header_bytes[:32]
                pn_bytes = header_bytes[32:36]
                n_bytes = header_bytes[36:40]
                dh_pub = x25519.X25519PublicKey.from_public_bytes(dh_pub_bytes)
                pn = int.from_bytes(pn_bytes, 'big')
                n = int.from_bytes(n_bytes, 'big')
                header = Header(dh_pub, pn, n)

                # Decrypt the message
                plaintext = self.ratchet_decrypt(header, ciphertext)
                print(f'{self.name} received:', plaintext.decode())

        except websockets.exceptions.ConnectionClosed:
            print("WebSocket connection closed")

    async def send_messages(self, websocket):
        while True:
            message = await asyncio.get_event_loop().run_in_executor(None, input, f'{self.name}: ')
            if message == '':
                continue
            plaintext = message.encode()
            header, ciphertext = self.ratchet_encrypt(plaintext)

            # Serialize the header
            header_bytes = serialize_header(header)
            header_length = len(header_bytes).to_bytes(4, 'big')

            # Prepare the ciphertext length
            ciphertext_length = len(ciphertext).to_bytes(4, 'big')

            # Send header length, header, ciphertext length, ciphertext
            await websocket.send(header_length + header_bytes + ciphertext_length + ciphertext)

    async def start_communication(self, websocket):
        receive_task = asyncio.create_task(self.handle_receive(websocket))
        send_task = asyncio.create_task(self.send_messages(websocket))
        await asyncio.gather(receive_task, send_task)
