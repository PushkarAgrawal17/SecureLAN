import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

KEY_DIR = "server_keys"

def ensure_server_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    private_path = os.path.join(KEY_DIR, "private.pem")
    public_path = os.path.join(KEY_DIR, "public.pem")
    if not os.path.exists(private_path):
        key = RSA.generate(3072)
        with open(private_path, "wb") as f:
            f.write(key.export_key("PEM"))
        with open(public_path, "wb") as f:
            f.write(key.publickey().export_key("PEM"))
    with open(private_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(public_path, "rb") as f:
        public_pem = f.read()
    return private_key, public_pem

def fingerprint(public_pem):
    key = RSA.import_key(public_pem)
    return hashlib.sha256(key.publickey().export_key(format="DER")).hexdigest()

def wrap_aes_key(public_pem, aes_key):
    public_key = RSA.import_key(public_pem)
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(aes_key)

def unwrap_aes_key(private_key, wrapped_key):
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped_key)

def new_gcm_encryptor(aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, mac_len=16)
    return cipher, cipher.nonce

def new_gcm_decryptor(aes_key, nonce):
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
