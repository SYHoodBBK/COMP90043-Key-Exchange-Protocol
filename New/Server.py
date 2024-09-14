import socket
import threading
import json
import signal
import sys


# Store requests in a global dictionary
keys_store = {}
messages_store = {}

def handle_client(client_socket):
    """Handle a client connection"""
    try:
        while True:
            # Receive the request
            data = client_socket.recv(4096).decode('utf-8')
            if not data.strip():  # 如果接收到的是空数据，提前返回
                print("Received empty request")
                return
            request = json.loads(data)
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
                        "message": "User not found"
                    }
            elif request["action"] == "disconnect":
                response = {
                    "status": "success",
                    "message": "Closing connection"
                }
                break
            else:
                response = {
                    "status": "error",
                    "message": "Invalid action"
                }
            # Send the response
            response = json.dumps(response).encode('utf-8')
            client_socket.sendall(response)
            print(f"Sent response: {response}")
    except Exception as e:
        print(f"Error processing request: {e}")
    # finally:
    #     client_socket.close()

def start_server(host='localhost', port=65432):
    """Start the server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1)

    print(f"Server listening on {host}:{port}...")

    try:
        while True:
            try:
                client_socket, client_address = server.accept()
                print(f"Connection from {client_address}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
    finally:
        server.close()
        sys.exit(0)

if __name__ == "__main__":
    start_server()