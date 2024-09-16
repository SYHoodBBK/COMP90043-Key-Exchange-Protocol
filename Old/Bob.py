from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import RawEncoder

import socket
import json


# 生成Bob的身份密钥 IKB
identity_key = SigningKey.generate()

# 生成Bob的被签名预密钥 SPKB
signed_prekey = SigningKey.generate()

# 对被签名预密钥进行签名
signature = identity_key.sign(
    signed_prekey.verify_key.encode(), encoder=RawEncoder)

# 生成一组临时预密钥 OPKB1, OPKB2, OPKB3...
one_time_prekeys = [PrivateKey.generate() for _ in range(3)]

# 输出结果
print("Bob的身份密钥 (IKB):", identity_key.encode(encoder=RawEncoder).hex())
print("Bob的被签名预密钥 (SPKB):", signed_prekey.encode(encoder=RawEncoder).hex())
print("预密钥签名 (Sig(IKB, Encode(SPKB))):", signature.signature.hex())

for i, opk in enumerate(one_time_prekeys, start=1):
    print(f"Bob的临时预密钥 OPKB{i}:", opk.encode(encoder=RawEncoder).hex())

def send_request(request_data, host='localhost', port=65432):
    """发送请求到服务器并接收响应"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # 连接到服务器
        client_socket.connect((host, port))

        # 发送请求数据
        client_socket.sendall(json.dumps(request_data).encode('utf-8'))

        # 接收响应数据
        response_data = client_socket.recv(1024)
        response = json.loads(response_data.decode('utf-8'))

        return response


# 发送Bob的身份密钥 IKB, Bob的被签名预密钥 SPKB, 预密钥签名 Sig(IKB, Encode(SPKB)) 和一组临时预密钥 OPKB1, OPKB2, OPKB3... 给Server

request_data = {
    "type": "store",
    "content": {
        "user": "Bob",
        # 公钥
        "identity_key": identity_key.verify_key.encode(encoder=RawEncoder).hex(),
        # 公钥
        "signed_prekey": signed_prekey.verify_key.encode(encoder=RawEncoder).hex(),
        "signature": signature.signature.hex(),  # 签名
        "one_time_prekeys": [
            # 公钥
            opk.public_key.encode(encoder=RawEncoder).hex() for opk in one_time_prekeys
        ]
    }
}

response = send_request(request_data)
print("响应数据:", response)