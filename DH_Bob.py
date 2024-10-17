# Bob.py

import asyncio
import websockets
from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization

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

# Create Bob's DoubleRatchetParticipant instance
bob = None

async def bob_server(websocket, path):
    global bob
    print('Bob connected')
    
    # Send Bob's initial DH public key to Alice
    await websocket.send(len(bob_initial_DH_pub_bytes).to_bytes(4, 'big') + bob_initial_DH_pub_bytes)

    # Start communication
    await bob.start_communication(websocket)

async def main():
    global bob
    HOST = 'localhost'
    PORT = 65432

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

    # Create Bob's DoubleRatchetParticipant instance
    bob = DoubleRatchetParticipant("Bob", SK, AD)
    bob.state = bob_state

    # Start WebSocket server
    async with websockets.serve(bob_server, HOST, PORT):
        print('Bob is listening...')
        await asyncio.Future()  # Run forever

if __name__ == '__main__':
    asyncio.run(main())
