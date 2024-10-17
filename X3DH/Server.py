import asyncio
import websockets
import json

# Store requests in global dictionaries
keys_store = {}
messages_store = {}

async def handle_client(websocket, path):
    """Handle a client connection"""
    try:
        async for message in websocket:
            request = json.loads(message)
            print(f"Received request: {request}")

            # Process the request
            if request["action"] == "register":
                # Bob registers his public key
                user_id = request["user_id"]
                keys_store[user_id] = {
                    "ik_B_public": request["identity_key"],
                    "spk_B_public": request["signed_prekey"],
                    "signature_B": request["signature"],
                    "opk_B_public": request["one_time_prekeys"]
                }
                response = {
                    "status": "success", 
                    "message": "Public keys registered"
                }
            elif request["action"] == "get_key":
                # Alice requests Bob's public key
                user_id = request["user_id"]
                if user_id in keys_store:
                    response = {
                        "status": "success",
                        "prekey_bundle": keys_store[user_id]
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "User not found"
                    }
            elif request["action"] == "send_message":
                # Alice sends a message to Bob
                user_id = request["user_id"]
                if user_id in keys_store:
                    if user_id not in messages_store:
                        messages_store[user_id] = []
                    messages_store[user_id].append(request["message"])
                    response = {
                        "status": "success",
                        "message": "Message received"
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "User not found"
                    }
            elif request["action"] == "get_messages":
                # Bob requests messages from Alice
                user_id = request["user_id"]
                if user_id in messages_store and messages_store[user_id]:
                    response = {
                        "status": "success",
                        "messages": messages_store[user_id]
                    }
                    messages_store[user_id] = []
                else:
                    response = {
                        "status": "error",
                        "message": "No messages found"
                    }
            else:
                response = {
                    "status": "error",
                    "message": "Invalid action"
                }
            
            # Send the response
            await websocket.send(json.dumps(response))
            print(f"Sent response: {response}")
    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected")

async def start_server(port=23456):
    """Start the WebSocket server"""
    server = await websockets.serve(handle_client, "0.0.0.0", port)
    print(f"Server listening on ws://0.0.0.0:{port}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(start_server())
