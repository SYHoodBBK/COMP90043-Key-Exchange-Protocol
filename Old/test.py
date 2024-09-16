# Double Ratchet of Alice

from nacl.utils import random
from nacl.secret import SecretBox
from nacl.encoding import RawEncoder
from nacl.hash import generichash

# 假设Bob和Alice已经通过服务器交换了公钥和预共享密钥
root_key = 61336238313463643030386163366330616135303439316431646637663230313165626665396534663462623735623336373962613138333362663537613036


def initialize_chain_keys(root_key):
    # 使用 PyNaCl 的 generichash 生成发送和接收棘轮密钥
    CK_s = generichash(b'ChainKey_Send', key=root_key,
                       encoder=RawEncoder)  # 生成发送棘轮密钥
    CK_r = generichash(b'ChainKey_Receive', key=root_key,
                       encoder=RawEncoder)  # 生成接收棘轮密钥
    return CK_s, CK_r


def symmetric_ratchet_update(CK):
    # 使用当前的棘轮密钥生成消息密钥
    MK = generichash(b'MessageKey', key=CK, encoder=RawEncoder)
    # 更新棘轮密钥，准备下一次使用
    new_CK = generichash(b'ChainKey', key=CK, encoder=RawEncoder)
    return new_CK, MK


def encrypt_message(plaintext, MK):
    # 使用消息密钥 (MK) 创建一个 SecretBox 对象
    box = SecretBox(MK)
    # 生成一个随机的 nonce (随机数)
    nonce = random(SecretBox.NONCE_SIZE)
    # 加密消息
    ciphertext = box.encrypt(plaintext.encode('utf-8'), nonce)
    return ciphertext


def decrypt_message(ciphertext, MK):
    # 使用消息密钥 (MK) 创建一个 SecretBox 对象
    box = SecretBox(MK)
    # 解密消息
    plaintext = box.decrypt(ciphertext).decode('utf-8')
    return plaintext


def send_message(plaintext, CK_s):
    # 对称棘轮更新，生成消息密钥并更新发送棘轮密钥
    CK_s, MK_s = symmetric_ratchet_update(CK_s)
    # 加密消息
    ciphertext = encrypt_message(plaintext, MK_s)
    return CK_s, ciphertext


def receive_message(ciphertext, CK_r):
    # 对称棘轮更新，生成消息密钥并更新接收棘轮密钥
    CK_r, MK_r = symmetric_ratchet_update(CK_r)
    # 解密消息
    plaintext = decrypt_message(ciphertext, MK_r)
    return CK_r, plaintext


# 假设Alice和Bob共享的root_key
root_key = 61336238313463643030386163366330616135303439316431646637663230313165626665396534663462623735623336373962613138333362663537613036
# 转换成字节串
root_key = root_key.to_bytes(64, 'big')

# 初始化棘轮密钥
CK_s, CK_r = initialize_chain_keys(root_key)

print("发送棘轮密钥 (CK_s):", CK_s.hex())
print("接收棘轮密钥 (CK_r):", CK_r.hex())

# 示例：Alice准备发送消息时
CK_s, MK_s = symmetric_ratchet_update(CK_s)

print("更新后的发送棘轮密钥 (CK_s):", CK_s.hex())
print("生成的消息密钥 (MK_s):", MK_s.hex())

# 示例：Alice加密发送给Bob的消息
message = "Hello, Bob!"
encrypted_message = encrypt_message(message, MK_s)

print("加密后的消息:", encrypted_message.hex())

# 示例：Bob接收到消息后，使用消息密钥解密
decrypted_message = decrypt_message(encrypted_message, MK_s)

print("解密后的消息:", decrypted_message)

# 初始化根密钥和棘轮密钥
# root_key = b'shared_root_key_example'
CK_s, CK_r = initialize_chain_keys(root_key)

# Alice发送消息给Bob
alice_message = "Hello, Bob!"
CK_s, encrypted_message = send_message(alice_message, CK_s)
print("更新后的发送棘轮密钥 (CK_s):", CK_s.hex())
print("Alice发送的加密消息:", encrypted_message.hex())

# Bob接收Alice的消息
CK_r, decrypted_message = receive_message(encrypted_message, CK_r)
print("Bob接收到的解密消息:", decrypted_message)
