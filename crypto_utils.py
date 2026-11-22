import hashlib
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


KEY_DIR = Path(__file__).resolve().parent / "server_keys"


def save_key(path, data):
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_bytes(data)
    temp_path.replace(path)


def ensure_server_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    private_path = KEY_DIR / "private.pem"
    public_path = KEY_DIR / "public.pem"

    # Generate a new pair only when neither key exists.
    if not private_path.exists() and not public_path.exists():
        key = RSA.generate(3072)

        save_key(private_path, key.export_key("PEM"))
        save_key(public_path, key.publickey().export_key("PEM"))

    # A public key alone cannot restore the private key.
    if not private_path.exists():
        raise FileNotFoundError(
            "Private RSA key is missing. Restore private.pem from a backup "
            "or remove the server_keys folder to generate a new identity."
        )

    with open(private_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Recreate a missing public key from the existing private key.
    expected_public = private_key.publickey().export_key("PEM")

    if not public_path.exists():
        save_key(public_path, expected_public)

    with open(public_path, "rb") as f:
        public_pem = f.read()

    public_key = RSA.import_key(public_pem)

    # Ensure both files belong to the same key pair.
    if public_key.export_key("DER") != private_key.publickey().export_key("DER"):
        raise ValueError(
            "RSA public and private keys do not match. "
            "Restore the correct key pair or generate a new identity."
        )

    return private_key, public_pem


def fingerprint(public_pem):
    key = RSA.import_key(public_pem)
    return hashlib.sha256(
        key.publickey().export_key(format="DER")
    ).hexdigest()


def wrap_aes_key(public_pem, aes_key):
    public_key = RSA.import_key(public_pem)
    return PKCS1_OAEP.new(
        public_key, hashAlgo=SHA256
    ).encrypt(aes_key)


def unwrap_aes_key(private_key, wrapped_key):
    return PKCS1_OAEP.new(
        private_key, hashAlgo=SHA256
    ).decrypt(wrapped_key)


def new_gcm_encryptor(aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, mac_len=16)
    return cipher, cipher.nonce


def new_gcm_decryptor(aes_key, nonce):
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
