import os
from typing import Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_random_salt(length: int) -> bytes:
    """Generate a random salt of a certain length."""
    return os.urandom(length)


def generate_key_pair() -> Tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
    """Create a public/private key pair for use in a Diffie-Hellman key exchange."""
    sk = ec.generate_private_key(ec.SECP256R1())  # type: taint[source]
    pk = sk.public_key()  # type: taint[sanitized]
    return pk, sk


def create_derived_key(
    pk: ec.EllipticCurvePublicKey, sk: ec.EllipticCurvePrivateKey
) -> bytes:
    """Create a symmetric key from the result of a Diffie-Hellman key exchange."""
    shared_secret = sk.exchange(ec.ECDH(), pk)
    key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"aesgcm").derive(
        shared_secret
    )  # type: taint[source]
    return key


def encrypt_message(key: bytes, plaintext: str, iv: bytes, aad=None) -> bytes:
    """Encrypt a message using AES-GCM."""
    return AESGCM(key).encrypt(iv, plaintext.encode(), aad)


def decrypt_message(key: bytes, ciphertext: bytes, iv: bytes, aad=None) -> str:
    """Decrypt a message using AES-GCM."""
    return AESGCM(key).decrypt(iv, ciphertext, aad).decode()


def serialize_key(
    key: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]
) -> bytes:
    """Serialize a key to a byte string in order to send it over the network."""
    encoding = serialization.Encoding.PEM
    if isinstance(key, ec.EllipticCurvePublicKey):
        bytes_ = key.public_bytes(
            encoding=encoding, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )  # type: taint[sanitized]
    else:
        bytes_ = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )  # type: taint[source]
    return bytes_


def parse_key(data: bytes) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(data)  # type: ignore
