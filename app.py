# app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from DoubleRatchetParticipant import DoubleRatchetParticipant, RatchetState
from functions import GENERATE_DH, x25519, serialization
from asgiref.sync import async_to_sync

from X3DH.Alice import get_alice_info
from X3DH.Bob import get_bob_info
import threading
import asyncio
from X3DH.Server import start_server

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Predefined parameters from X3DH


# Create Alice and Bob instances
alice = DoubleRatchetParticipant("Alice", None, None)
bob = DoubleRatchetParticipant("Bob", None, None)

# Initialize Bob's DH key pair
# bob_initial_DH = GENERATE_DH()
# bob_initial_DH_pub_bytes = bob_initial_DH.public_key().public_bytes(
#     encoding=serialization.Encoding.Raw,
#     format=serialization.PublicFormat.Raw
# )

# Add a new variable to track Bob's connection status
bob_connected = False

@app.route('/')
def index():
    return render_template('index.html', bob_connected=bob_connected)

@app.route('/alice')
def alice_page():
    global bob_connected
    if not bob_connected:
        return redirect(url_for('index'))
    return render_template('alice.html')

@app.route('/bob')
def bob_page():
    global bob_connected
    if bob_connected:
        return redirect(url_for('index'))
    return render_template('bob.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('initialize_alice')
def initialize_alice():
    global alice
    share_SK, share_AD, SPKB, alice_private_key = async_to_sync(get_alice_info)()
    alice.SK = share_SK
    alice.AD = share_AD

    
    alice_state = RatchetState(
        RK=share_SK,
        DHs=alice_private_key,
        DHr=SPKB,
        CKs=None,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        MKSKIPPED={}
    )
    alice.state = alice_state
    emit('Alice initialization_complete')

@socketio.on('initialize_bob')
def initialize_bob():
    global bob, bob_connected
    print("start initialize bob")
    bob_connected = True
    
    # 使用 async_to_sync 来运行异步函数
    share_SK, share_AD, SPKA, bob_private_key = async_to_sync(get_bob_info)()
    
    bob.SK = share_SK
    bob.AD = share_AD


    bob_state = RatchetState(
        RK=share_SK,
        DHs=bob_private_key,
        # DHr=SPKA,
        DHr=None,
        CKs=None,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        MKSKIPPED={}
    )
    bob.state = bob_state

    emit('Bob initialization_complete')
    emit('bob_connected', broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    sender = data['sender']
    message = data['message']
    
    if sender == 'Alice':
        header, ciphertext, alice_ratchet_performed = alice.ratchet_encrypt(message.encode())
        bob_plaintext, bob_ratchet_performed = bob.ratchet_decrypt(header, ciphertext)
        if alice_ratchet_performed:
            emit('receive_message', {'sender': 'System', 'message': 'Alice performed a send ratchet step'}, broadcast=True)
        if bob_ratchet_performed:
            emit('receive_message', {'sender': 'System', 'message': 'Bob performed a receive ratchet step'}, broadcast=True)
        emit('receive_message', {'sender': 'Alice', 'message': message}, broadcast=True)
    else:
        if bob.state.DHr is None:
            bob.state.DHr = alice.state.DHs.public_key()
        header, ciphertext, bob_ratchet_performed = bob.ratchet_encrypt(message.encode())
        alice_plaintext, alice_ratchet_performed = alice.ratchet_decrypt(header, ciphertext)
        if bob_ratchet_performed:
            emit('receive_message', {'sender': 'System', 'message': 'Bob performed a send ratchet step'}, broadcast=True)
        if alice_ratchet_performed:
            emit('receive_message', {'sender': 'System', 'message': 'Alice performed a receive ratchet step'}, broadcast=True)
        emit('receive_message', {'sender': 'Bob', 'message': message}, broadcast=True)

# 添加一个函数来在后台运行 WebSocket 服务器
def run_websocket_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())

if __name__ == '__main__':
    # 在后台线程中启动 WebSocket 服务器
    websocket_thread = threading.Thread(target=run_websocket_server, daemon=True)
    websocket_thread.start()
    
    # 启动 Flask 应用，添加 allow_unsafe_werkzeug=True 参数
    socketio.run(app, host='0.0.0.0', port=5000, use_reloader=False, allow_unsafe_werkzeug=True,debug=False)
