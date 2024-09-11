import tool
import os


bob_IKB_private_bytes, bob_IKB_public_bytes = tool.generateKey()
bob_SPKB_private_bytes, bob_SPKB_public_bytes = tool.generateKey()

# # D3DH预密钥签名Sig
# def sign_prekey(IKB_public_bytes, SPKB_public_bytes):
#     # 生成 32 字节的随机私钥
#     private_key_bytes = os.urandom(32)

#     # 创建私钥对象
#     private_key = tool.X
    