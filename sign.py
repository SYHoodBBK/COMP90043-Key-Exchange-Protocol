
import hashlib

# 常量定义
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

# 哈希函数，使用 SHA-512


def H(m):
  return hashlib.sha512(m).digest()

# 模幂运算函数


def expmod(b, e, m):
  if e == 0:
    return 1
  t = expmod(b, e/2, m)**2 % m
  if e & 1:
    t = (t*b) % m
  return t

# 求逆元函数


def inv(x):
  return expmod(x, q-2, q)


# 常量 d 和 I 的定义
d = -121665 * inv(121666)
I = expmod(2, (q-1)/4, q)

# 根据 y 坐标恢复 x 坐标


def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  x = expmod(xx, (q+3)/8, q)
  if (x*x - xx) % q != 0:
    x = (x*I) % q
  if x % 2 != 0:
    x = q-x
  return x


# 基点 B 的定义
By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q, By % q]

# Edwards 曲线加法


def edwards(P, Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
  return [x3 % q, y3 % q]

# 标量乘法


def scalarmult(P, e):
  if e == 0:
    return [0, 1]
  Q = scalarmult(P, e/2)
  Q = edwards(Q, Q)
  if e & 1:
    Q = edwards(Q, P)
  return Q

# 编码整数


def encodeint(y):
  bits = [(y >> i) & 1 for i in range(b)]
  return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

# 编码点


def encodepoint(P):
  x = P[0]
  y = P[1]
  bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
  return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

# 获取哈希值的第 i 位


def bit(h, i):
  return (ord(h[i/8]) >> (i % 8)) & 1

# 生成公钥


def publickey(sk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h, i) for i in range(3, b-2))
  A = scalarmult(B, a)
  return encodepoint(A)

# 哈希整数


def Hint(m):
  h = H(m)
  return sum(2**i * bit(h, i) for i in range(2*b))

# 生成签名


def signature(m, sk, pk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h, i) for i in range(3, b-2))
  r = Hint(''.join([h[i] for i in range(b/8, b/4)]) + m)
  R = scalarmult(B, r)
  S = (r + Hint(encodepoint(R) + pk + m) * a) % l
  return encodepoint(R) + encodeint(S)

# 检查点是否在曲线上


def isoncurve(P):
  x = P[0]
  y = P[1]
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

# 解码整数


def decodeint(s):
  return sum(2**i * bit(s, i) for i in range(0, b))

# 解码点


def decodepoint(s):
  y = sum(2**i * bit(s, i) for i in range(0, b-1))
  x = xrecover(y)
  if x & 1 != bit(s, b-1):
    x = q-x
  P = [x, y]
  if not isoncurve(P):
    raise Exception("decoding point that is not on curve")
  return P

# 验证签名


def checkvalid(s, m, pk):
  if len(s) != b/4:
    raise Exception("signature length is wrong")
  if len(pk) != b/8:
    raise Exception("public-key length is wrong")
  R = decodepoint(s[0:b/8])
  A = decodepoint(pk)
  S = decodeint(s[b/8:b/4])
  h = Hint(encodepoint(R) + pk + m)
  if scalarmult(B, S) != edwards(R, scalarmult(A, h)):
    raise Exception("signature does not pass verification")


