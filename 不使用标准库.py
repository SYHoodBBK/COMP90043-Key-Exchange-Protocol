P = 2 ** 255 - 19
_A = 486662


def _point_add(point_n, point_m, point_diff):
    """Given the projection of two points and their difference, return their sum"""
    (xn, zn) = point_n
    (xm, zm) = point_m
    (x_diff, z_diff) = point_diff
    x = (z_diff << 2) * (xm * xn - zm * zn) ** 2
    z = (x_diff << 2) * (xm * zn - zm * xn) ** 2
    return x % P, z % P


def _point_double(point_n):
    """Double a point provided in projective coordinates"""
    (xn, zn) = point_n
    xn2 = xn ** 2
    zn2 = zn ** 2
    x = (xn2 - zn2) ** 2
    xzn = xn * zn
    z = 4 * xzn * (xn2 + _A * xzn + zn2)
    return x % P, z % P


def _const_time_swap(a, b, swap):
    """Swap two values in constant time"""
    index = int(swap) * 2
    temp = (a, b, b, a)
    return temp[index:index+2]


def _raw_curve25519(base, n):
    """Raise the point base to the power n"""
    zero = (1, 0)
    one = (base, 1)
    mP, m1P = zero, one

    for i in reversed(range(256)):
        bit = bool(n & (1 << i))
        mP, m1P = _const_time_swap(mP, m1P, bit)
        mP, m1P = _point_double(mP), _point_add(mP, m1P, one)
        mP, m1P = _const_time_swap(mP, m1P, bit)

    x, z = mP
    inv_z = pow(z, P - 2, P)
    return (x * inv_z) % P


def _unpack_number(s):
    """Unpack 32 bytes to a 256 bit value"""
    if len(s) != 32:
        raise ValueError('Curve25519 values must be 32 bytes')
    return int.from_bytes(s, "little")


def _pack_number(n):
    """Pack a value into 32 bytes"""
    return n.to_bytes(32, "little")


def _fix_secret(n):
    """Mask a value to be an acceptable exponent"""
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


def curve25519_base(secret_raw):
    """Raise the generator point to a given power"""
    secret = _fix_secret(_unpack_number(secret_raw))
    return _pack_number(_raw_curve25519(9, secret))


def bytes_to_int(byte_data: bytes) -> int:
    """
    将字节数据转换为整数

    :param byte_data: 字节数据
    :return: 整数表示
    """
    return int.from_bytes(byte_data, byteorder='big')


private_key = 51344065330787927104900335251434126955494588909159553146754810308293679717200

# 生成公钥
public_key = curve25519_base(private_key.to_bytes(32, 'big'))
print("Private Key:", private_key)
print("Public Key:", bytes_to_int(public_key))
