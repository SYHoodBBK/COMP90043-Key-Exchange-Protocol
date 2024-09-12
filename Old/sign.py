#!/usr/bin/env python3

import hashlib
import random

# prime = 57896044618658097711785492504343953926634992332820282019728792003956564819949L
# Fp = 2^255 - 19
p = pow(2, 255) - 19
# G Point
base_point = 15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960


def modulus(a, p):
	return a % p


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

# modular inverse of a mod m


def mod_inverse(a, m):
	a = modulus(a, m)

	if gcd(a, m) != 1:
		return None  # no mod inverse if a & m aren't relatively prime

	# Calculate using the Extended Euclidean Algorithm:
	u1, u2, u3 = 1, 0, a
	v1, v2, v3 = 0, 1, m
	while v3 != 0:
		q = u3 // v3  # // is the integer division operator
		v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q *
                                           v2), (u3 - q * v3), v1, v2, v3
	return u1 % m

# P + Q = R
# x3 = (x1*y2 + y1*x2)/(1 + d*x1*x2*y1*y2)
# y3 = (y1*y2 - a*x1*x2)/(1 - d*x1*x2*y1*y2)


def point_addition(P, Q, a, d, mod):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = modulus(modulus(x1*y2 + y1*x2, mod) *
                 mod_inverse(1 + d*x1*x2*y1*y2, mod), mod)
    y3 = modulus(modulus(y1*y2 - a*x1*x2, mod) *
                 mod_inverse(1 - d*x1*x2*y1*y2, mod), mod)
    return x3, y3

# k*G = k*P = R


def point_scalar_multiplication(k, P, a, d, mod):

	addition_point = (P[0], P[1])

	k_binary = bin(k)  # 0b1111111001
	k_binary = k_binary[2:len(k_binary)]  # 1111111001

	for i in range(1, len(k_binary)):
		current_bit = k_binary[i: i+1]
		# always apply doubling: 2*P
		addition_point = point_addition(addition_point, addition_point, a, d, mod)

		if current_bit == '1':
			# add base point
			addition_point = point_addition(addition_point, P, a, d, mod)

	return addition_point


def text_to_int(text):
	encoded_text = text.encode('utf-8')
	hex_text = encoded_text.hex()
	int_text = int(hex_text, 16)
	return int_text


def hashing(message):
	return int(hashlib.sha512(str(message).encode("utf-8")).hexdigest(), 16)


# Ed25519's Twisted Edwards Curve
# a*x^2 + y^2  = 1 + d*x^2*y^2 where a = -1 and d = -121665/121666 = -121665*(1/121666) = -121665*Inverse(121666)
a = -1
d = modulus(-121665 * mod_inverse(121666, p), p)

private_key = random.getrandbits(256)  # 32 byte secret key
public_key = point_scalar_multiplication(private_key, base_point, a, d, p)

private_key = 30556489615831614089964895004708150062492616274899789558508508418377194326322
public_key = point_scalar_multiplication(private_key, base_point, a, d, p)
print("public_key: ", public_key)

# Signing Message
message = text_to_int("MathxH Chen")
# Generating random key based on the hash of the message.
# In this way, every message has a different random key.
r = modulus(hashing(hashing(message) + message), p)
# Random key times(r) base point will be random point R and it is a type of curve point.
# Extracting secret random key r from known random point R is a really hard problem(ECDLP)
R = point_scalar_multiplication(r, base_point, a, d, p)
# combination of the random point(R) x-coordinate, public key x-coordinate and the message will be stored in the variable h after hashing.
# This can be calculated by receiver party, too
h = modulus(hashing(R[0] + public_key[0] + message), p)
s = (r + h * private_key)

# Verify Signature of the message

# R[0] is random point(R) x-coordinate
# public_key[0] is public key point x-coordinate
h = modulus(hashing(R[0] + public_key[0] + message), p)
P1 = point_scalar_multiplication(s, base_point, a, d, p)
P2 = point_addition(R, point_scalar_multiplication(
	h, public_key, a, d, p), a, d, p)

# P1 = P2
if P1[0] == P2[0] and P1[1] == P2[1]:
	print("signature MathxH Chen valid")
else:
	print("signature MathxH Chen invaid")

# message changed by attacker
message = text_to_int("Lynn Lee")
h = modulus(hashing(R[0] + public_key[0] + message), p)
P1 = point_scalar_multiplication(s, base_point, a, d, p)
P2 = point_addition(R, point_scalar_multiplication(
	h, public_key, a, d, p), a, d, p)

if P1[0] == P2[0] and P1[1] == P2[1]:
	print("signature MathxH Chen valid")
else:
	print("signature MathxH Chen invaid")
