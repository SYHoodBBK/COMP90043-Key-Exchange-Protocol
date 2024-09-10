import os


def generate_private_key():
    # 生成一个 32 字节（256 位）的随机数作为私钥
    private_key = int.from_bytes(os.urandom(32), 'little')  # 小端字节序

    # Curve25519 的私钥需要经过一些位操作掩码处理
    private_key &= (1 << 254) - 8  # 清除最低的 3 位
    private_key |= 1 << 254  # 设置第 254 位
    return private_key



# Curve25519 的素数模数
p = 2**255 - 19

A = 486662  # 曲线参数
A24 = (A + 2) // 4  # (A + 2) / 4

# 椭圆曲线上的模逆运算


def modular_inverse(a, p):
    return pow(a, p-2, p)


def point_add(x1, z1, x2, z2, x_diff, z_diff):
    t1 = (x1 - z1) * (x2 + z2) % p
    t2 = (x1 + z1) * (x2 - z2) % p
    x3 = (t1 + t2) ** 2 % p
    z3 = (t1 - t2) ** 2 % p
    return (x3 * z_diff % p, z3 * x_diff % p)


def point_double(x1, z1, A24):
    t1 = (x1 + z1) ** 2 % p
    t2 = (x1 - z1) ** 2 % p
    x3 = t1 * t2 % p
    z3 = (t1 - t2) * (t2 + A24 * (t1 - t2) % p) % p
    return (x3, z3)


def montgomery_ladder(k):
    x1 = 9  # G 点
    x2, z2 = 1, 0  # R0 = 0 点
    x3, z3 = x1, 1  # R1 = P 点

    for i in range(255, -1, -1):  # 从第 255 位开始
        bit = (k >> i) & 1

        if bit == 0:
            x2, z2 = point_double(x2, z2, A24)
            x3, z3 = point_add(x2, z2, x3, z3, x1, 1)
        else:
            x3, z3 = point_double(x3, z3, A24)
            x2, z2 = point_add(x2, z2, x3, z3, x1, 1)

    z_inv = modular_inverse(z2, p)
    return x2 * z_inv % p


private_key = 51344065330787927104900335251434126955494588909159553146754810308293679717200
public_key = montgomery_ladder(private_key)
print("Private Key:", private_key)
print("Public Key:", public_key)

