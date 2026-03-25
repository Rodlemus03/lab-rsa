import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from generar_claves import generar_par_claves


def encrypt_document(document: bytes, recipient_public_key_pem: bytes) -> bytes:
    aes_key = os.urandom(32)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(document)

    public_key = RSA.import_key(recipient_public_key_pem)
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    package = [
        struct.pack(">H", len(encrypted_key)),
        encrypted_key,
        aes_cipher.nonce,
        tag,
        ciphertext,
    ]
    return b"".join(package)

def decrypt_document(pkg: bytes, recipient_private_key_pem: bytes) -> bytes:
    encrypted_key_len = struct.unpack(">H", pkg[:2])[0]
    start = 2
    end = start + encrypted_key_len
    encrypted_key = pkg[start:end]
    nonce = pkg[end:end + 16]
    tag = pkg[end + 16:end + 32]
    ciphertext = pkg[end + 32:]

    private_key = RSA.import_key(recipient_private_key_pem, passphrase="lab04uvg")
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_key)

    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return aes_cipher.decrypt_and_verify(ciphertext, tag)

if __name__ == '__main__':
    generar_par_claves(2048)

    with open("public_key.pem", "rb") as f: pub = f.read()
    with open("private_key.pem", "rb") as f: priv = f.read()

    # Generen un cifrado de un texto
    doc = b"Contrato de confidencialidad No. 2025-GT-001"
    pkg = encrypt_document(doc, pub)
    resultado = decrypt_document(pkg, priv)


    # Prueba con archivo de 1 MB (simula un contrato real)
    doc_grande = os.urandom(1024 * 1024)
    pkg2 = encrypt_document(doc_grande, pub)
    assert decrypt_document(pkg2, priv) == doc_grande
    print("Archivo 1 MB: OK")
