from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import RawEncoder

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
