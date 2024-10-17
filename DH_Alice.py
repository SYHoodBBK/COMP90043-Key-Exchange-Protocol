# Alice.py

import asyncio
import websockets
from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519

# Predefined parameters from X3DH
SK = b'shared_secret_key_from_X3DH'
AD = b'associated_data_from_X3DH'

async def alice_client():
    uri = f"ws://localhost:65432"
    async with websockets.connect(uri) as websocket:
        print("Alice connected")

        # Receive Bob's initial DH public key
        dh_pub_message = await websocket.recv()
        dh_pub_length = int.from_bytes(dh_pub_message[:4], 'big')
        dh_pub_bytes = dh_pub_message[4:]
        bob_initial_DH_pub = x25519.X25519PublicKey.from_public_bytes(dh_pub_bytes)

        # Initialize Alice's state
        alice_state = RatchetState(
            RK=SK,
            DHs=GENERATE_DH(),
            DHr=bob_initial_DH_pub,
            CKs=None,
            CKr=None,
            Ns=0,
            Nr=0,
            PN=0,
            MKSKIPPED={}
        )

        # Create Alice's DoubleRatchetParticipant instance
        alice = DoubleRatchetParticipant("Alice", SK, AD)
        alice.state = alice_state

        # Start communication
        await alice.start_communication(websocket)

if __name__ == '__main__':
    asyncio.run(alice_client())
