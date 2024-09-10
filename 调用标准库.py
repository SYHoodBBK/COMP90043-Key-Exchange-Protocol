import nacl.public

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


private_key = 51344065330787927104900335251434126955494588909159553146754810308293679717200
print("Private Key:", private_key)
public_key = generate_public_key(private_key.to_bytes(32, 'big'))
print("Public Key:", bytes_to_int(public_key))
