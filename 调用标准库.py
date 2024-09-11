import nacl.signing
import nacl.public
import os


def generate_public_key(private_key: bytes) -> bytes:
    """
    使用curve25519从私钥计算公钥

    :param private_key: 32字节的私钥
    :return: 32字节的公钥
    """
    private_key_obj = nacl.public.PrivateKey(private_key)
    public_key_obj = private_key_obj.public_key
    return bytes(public_key_obj)


def bytes_to_int(byte_data: bytes) -> int:
    """
    将字节数据转换为整数

    :param byte_data: 字节数据
    :return: 整数表示
    """
    return int.from_bytes(byte_data, byteorder='big')


def sign_prekey(IKB_public_key: bytes, SPKB_public_key: bytes) -> bytes:
    """
    生成D3DH预密钥签名Sig

    :param IKB_public_key: IKB公钥
    :param SPKB_public_key: SPKB公钥
    :return: D3DH预密钥签名Sig
    """
    # 生成 32 字节的随机私钥
    private_key_bytes = os.urandom(32)

    # 创建签名密钥对象
    signing_key = nacl.signing.SigningKey(private_key_bytes)

    # 计算签名
    signature = signing_key.sign(IKB_public_key + SPKB_public_key).signature

    return signature


# 生成IKB密钥对
IKB_private_key = nacl.public.PrivateKey.generate()
IKB_public_key = IKB_private_key.public_key
print(IKB_public_key)

# 生成SPKB密钥对
SPKB_private_key = nacl.public.PrivateKey.generate()
SPKB_public_key = SPKB_private_key.public_key

# 生成D3DH预密钥签名Sig
sig = sign_prekey(bytes(IKB_public_key), bytes(SPKB_public_key))
print(sig)
