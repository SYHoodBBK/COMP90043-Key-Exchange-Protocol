# functions.py

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Header:
    def __init__(self, dh_pub, pn, n):
        self.dh = dh_pub
        self.pn = pn
        self.n = n


def GENERATE_DH():
    """Generates a new Diffie-Hellman key pair based on Curve25519."""
    private_key = x25519.X25519PrivateKey.generate()
    return private_key


def DH(dh_pair, dh_pub):
    """
    Performs Diffie-Hellman key exchange between a private key and a public key.
    Returns the shared secret.
    """
    shared_key = dh_pair.exchange(dh_pub)
    return shared_key


def KDF_RK(rk, dh_out):
    """
    Key Derivation Function for Root Key (RK).
    Derives a new root key and chain key from the current root key and DH output.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes root key + 32 bytes chain key
        salt=rk,
        info=b"DoubleRatchetKDFRK",
    )
    output = hkdf.derive(dh_out)
    new_rk = output[:32]
    ck = output[32:]
    return (new_rk, ck)


def KDF_CK(ck):
    """
    Key Derivation Function for Chain Key (CK).
    Derives a new chain key and message key from the current chain key.
    """
    hmac_key = hmac.HMAC(ck, hashes.SHA256())
    hmac_key.update(b'\x02')
    new_ck = hmac_key.finalize()

    hmac_key = hmac.HMAC(ck, hashes.SHA256())
    hmac_key.update(b'\x01')
    mk = hmac_key.finalize()

    return (new_ck, mk)


def ENCRYPT(mk, plaintext, associated_data):
    """
    Encrypts the plaintext using the message key (mk) and associated data.
    Returns the ciphertext with appended HMAC for authentication.
    """
    # Derive encryption key, authentication key, and IV
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,  # 32 + 32 + 16 bytes
        salt=b'\x00' * 32,
        info=b'DoubleRatchetMessageKeys',
    )
    key_material = hkdf.derive(mk)
    ek = key_material[:32]
    ak = key_material[32:64]
    iv = key_material[64:80]

    # Encrypt plaintext
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(ek), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Compute HMAC
    h = hmac.HMAC(ak, hashes.SHA256())
    h.update(associated_data + ciphertext)
    hmac_output = h.finalize()

    # Append HMAC to ciphertext
    encrypted_message = ciphertext + hmac_output
    return encrypted_message


def DECRYPT(mk, encrypted_message, associated_data):
    """
    Decrypts the encrypted_message using the message key (mk) and associated data.
    Verifies the HMAC and returns the original plaintext.
    """
    # Derive encryption key, authentication key, and IV
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,  # 32 + 32 + 16 bytes
        salt=b'\x00' * 32,
        info=b'DoubleRatchetMessageKeys',
    )
    key_material = hkdf.derive(mk)
    ek = key_material[:32]
    ak = key_material[32:64]
    iv = key_material[64:80]

    # Separate ciphertext and HMAC
    if len(encrypted_message) < 32:
        raise Exception('Ciphertext too short')

    hmac_received = encrypted_message[-32:]
    ciphertext = encrypted_message[:-32]

    # Verify HMAC
    h = hmac.HMAC(ak, hashes.SHA256())
    h.update(associated_data + ciphertext)
    h.verify(hmac_received)

    # Decrypt ciphertext
    cipher = Cipher(algorithms.AES(ek), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def HEADER(dh_pair, pn, n):
    """
    Creates a new message header containing the DH ratchet public key,
    the previous chain length pn, and the message number n.
    """
    dh_pub = dh_pair.public_key()
    return Header(dh_pub, pn, n)


def serialize_header(header):
    """Serializes the header into bytes."""
    dh_bytes = header.dh.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pn_bytes = header.pn.to_bytes(4, 'big')
    n_bytes = header.n.to_bytes(4, 'big')
    return dh_bytes + pn_bytes + n_bytes


def CONCAT(ad, header):
    """
    Encodes a message header into a parseable byte sequence,
    prepends the ad byte sequence, and returns the result.
    """
    header_bytes = serialize_header(header)
    ad_length = len(ad).to_bytes(4, 'big')
    result = ad_length + ad + header_bytes
    return result
