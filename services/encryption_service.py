import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file_hybrid(input_path, output_path, user_public_key_pem):
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    public_key = serialization.load_pem_public_key(user_public_key_pem.encode("utf-8"))
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return base64.b64encode(encrypted_aes_key).decode("utf-8"), base64.b64encode(nonce).decode("utf-8")


def decrypt_file_hybrid(input_path, output_path, user_private_key_pem, encrypted_aes_key_b64, nonce_b64):
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    nonce = base64.b64decode(nonce_b64)

    private_key = serialization.load_pem_private_key(
        user_private_key_pem.encode("utf-8"), password=None
    )
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    with open(input_path, "rb") as f:
        ciphertext = f.read()

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(plaintext)
