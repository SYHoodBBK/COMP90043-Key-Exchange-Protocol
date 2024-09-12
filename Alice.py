
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import RawEncoder
from nacl.hash import sha256

import socket
import json


# 生成Alice的身份密钥 IKA
identity_key = SigningKey.generate()

# 生成Alice的被签名预密钥 SPKA
signed_prekey = SigningKey.generate()

# 对被签名预密钥进行签名
signature = identity_key.sign(
    signed_prekey.verify_key.encode(), encoder=RawEncoder)

# 生成一组临时预密钥 OPKA1, OPKA2, OPKA3...
one_time_prekeys = [PrivateKey.generate() for _ in range(3)]

# 输出结果
print("Alice的身份密钥 (IKA):", identity_key.encode(encoder=RawEncoder).hex())
print("Alice的被签名预密钥 (SPKA):", signed_prekey.encode(encoder=RawEncoder).hex())
print("预密钥签名 (Sig(IKA, Encode(SPKA))):", signature.signature.hex())

for i, opk in enumerate(one_time_prekeys, start=1):
    print(f"Alice的临时预密钥 OPKA{i}:", opk.encode(encoder=RawEncoder).hex())


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


# 发送Alice的身份密钥 IKA, Alice的被签名预密钥 SPKA, 预密钥签名 Sig(IKA, Encode(SPKA)) 和一组临时预密钥 OPKA1, OPKA2, OPKA3... 给Server

request_data = {
    "type": "store",
    "content":
        {
            "user": "Alice",
            "identity_key": identity_key.encode(encoder=RawEncoder).hex(),
            "signed_prekey": signed_prekey.encode(encoder=RawEncoder).hex(),
            "signature": signature.signature.hex(),
            "one_time_prekeys": [
                opk.encode(encoder=RawEncoder).hex() for opk in one_time_prekeys
            ]
        }
}

# response = send_request(request_data)
# print("响应数据:", response)

# Alice 请求Bob的身份密钥 IKB, Bob的被签名预密钥 SPKB, 预密钥签名 Sig(IKB, Encode(SPKB)) 和一组临时预密钥 OPKB1, OPKB2, OPKB3...
request_data = {
    "type": "retrieve",
    "user": "Bob"
}

response = send_request(request_data)
print("响应数据:", response)

if response["status"] == "success":
    bob_data = response["content"][0]

    bob_identity_key = VerifyKey(bytes.fromhex(
        bob_data["identity_key"]), encoder=RawEncoder)
    bob_signed_prekey = VerifyKey(bytes.fromhex(
        bob_data["signed_prekey"]), encoder=RawEncoder)
    # 验证签名
    try:
        bob_identity_key.verify(bytes.fromhex(
            bob_data["signed_prekey"]), bytes.fromhex(bob_data["signature"]))
        print("签名验证成功")
    except Exception:
        print("签名验证失败")
        exit(1)
        
    bob_one_time_prekeys = PublicKey(
        bytes.fromhex(bob_data["one_time_prekeys"]), encoder=RawEncoder)
    
    # 生成临时密钥对 EKA
    ephemeral_key = PrivateKey.generate()

    # 计算DH1, DH2, DH3
    DH1 = Box(identity_key.to_curve25519_private_key(),
              bob_signed_prekey.to_curve25519_public_key()).shared_key()
    DH2 = Box(ephemeral_key,
              bob_identity_key.to_curve25519_public_key()).shared_key()
    DH3 = Box(ephemeral_key,
              bob_signed_prekey.to_curve25519_public_key()).shared_key()

    # 检查是否有OPKB
    if bob_one_time_prekeys:
        # 使用第一个临时预密钥 OPKB1
        OPKB = bob_one_time_prekeys
        DH4 = Box(ephemeral_key, OPKB).shared_key()
        SK = sha256(DH1 + DH2 + DH3 + DH4, encoder=RawEncoder).hex()
    else:
        SK = sha256(DH1 + DH2 + DH3, encoder=RawEncoder).hex()

    print("共享密钥 (SK):", SK)

    # 使用身份信息计算“associated data”即AD
    IKA = identity_key.public_key.encode(encoder=RawEncoder)
    IKB = bob_identity_key.encode(encoder=RawEncoder)
    AD = IKA + IKB

    # 发送身份密钥IKA, 临时密钥EKA, 使用的Bob的被签名预密钥的标志号（如果使用了OPKB，那么还有OPKB的标志号），一段初始化文本，AEAD模式加密，其中AD作为输入的associated data，使用SK（或HKDF函数拓展SK）作为加密的密钥
    