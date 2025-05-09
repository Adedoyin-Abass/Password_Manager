import os
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import json

# --- Helper Functions ---
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Important: Use a high number of iterations
        salt=salt,
        length=32,  # 256 bits
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts the given data using Fernet symmetric encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts the given data using Fernet."""
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data
    except InvalidToken:
        print("Invalid Token - Incorrect Master Password")
        return None

def store_data(filename: str, data: bytes):
    """Stores the encrypted data to a file."""
    with open(filename, 'wb') as f:
        f.write(data)

def load_data(filename: str) -> bytes:
    """Loads the encrypted data from a file."""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            return data
    except FileNotFoundError:
        return None

def generate_salt() -> bytes:
    """Generates a random salt."""
    return os.urandom(16)

def generate_password(length=12):
    """Generates a random password of the specified length."""
    import random
    import string
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def generate_rsa_key_pair():
    """Generates an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    """Serializes the private key to bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(private_key_bytes):
    """Deserializes the private key from bytes."""
    return serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

def serialize_public_key(public_key):
    """Serializes the public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """Deserializes the public key from bytes."""
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

def encrypt_fernet_key(fernet_key: bytes, public_key):
    """Encrypts the Fernet key using the RSA public key."""
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_fernet_key(encrypted_fernet_key: bytes, private_key):
    """Decrypts the Fernet key using the RSA private key."""
    decrypted_key = private_key.decrypt(
        encrypted_fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def load_keys_and_salt(filename: str):
    """Loads the salt and RSA keys, or generates them if they don't exist."""
    salt_filename = filename + ".salt"
    private_key_filename = filename + ".private_key"
    public_key_filename = filename + ".public_key"
    fernet_key_filename = filename + ".fernet_key"

    salt = None
    private_key = None
    public_key = None
    encrypted_fernet_key = None

    try:
        with open(salt_filename, 'rb') as f:
            salt = f.read()
    except FileNotFoundError:
        salt = generate_salt()
        with open(salt_filename, 'wb') as f:
            f.write(salt)

    try:
        with open(private_key_filename, 'rb') as f:
            private_key_bytes = f.read()
            private_key = deserialize_private_key(private_key_bytes)
    except FileNotFoundError:
        private_key, public_key = generate_rsa_key_pair()
        with open(private_key_filename, 'wb') as f:
            private_key_bytes = serialize_private_key(private_key)
            f.write(private_key_bytes)
        with open(public_key_filename, 'wb') as f:
            public_key_bytes = serialize_public_key(public_key)
            f.write(public_key_bytes)
    else:
        try:
            with open(public_key_filename, 'rb') as f:
                public_key_bytes = f.read()
                public_key = deserialize_public_key(public_key_bytes)
        except FileNotFoundError:
            # This should ideally not happen if private key exists
            raise FileNotFoundError("Public key file missing!")

    try:
        with open(fernet_key_filename, 'rb') as f:
            encrypted_fernet_key = f.read()
    except FileNotFoundError:
        # Generate a new Fernet key, encrypt it, and store it
        fernet_key = Fernet.generate_key()
        encrypted_fernet_key = encrypt_fernet_key(fernet_key, public_key)
        with open(fernet_key_filename, 'wb') as f:
            f.write(encrypted_fernet_key)

    return salt, private_key, public_key, encrypted_fernet_key

# --- Main Functions ---

def add_password(filename: str, master_password: str):
    """Adds a new website/password pair to the encrypted storage."""
    website = input("Enter website/application name: ")
    password = getpass.getpass("Enter password (or type 'generate' to create one): ")
    if password.lower() == 'generate':
        password = generate_password()
        print(f"Generated Password: {password}") #tell user generated password

    salt, private_key, public_key, encrypted_fernet_key = load_keys_and_salt(filename)
    derived_key = derive_key_from_password(master_password, salt)
    decrypted_fernet_key = decrypt_fernet_key(encrypted_fernet_key, private_key)

    if decrypted_fernet_key is None:
        print("Authentication failed.")
        return

    data_to_encrypt = f"{website}:{password}".encode()
    encrypted_data = encrypt_data(data_to_encrypt, decrypted_fernet_key)

    # Load existing data, append, and save
    existing_data = load_data(filename)
    if existing_data:
        combined_data = existing_data + b"||" + encrypted_data #delimiter
    else:
        combined_data = encrypted_data
    store_data(filename, combined_data)
    print(f"Password for {website} added successfully.")

def retrieve_password(filename: str, master_password: str):
    """Retrieves a password for a given website/application."""

    website_to_find = input("Enter website/application name to retrieve password: ")
    salt, private_key, public_key, encrypted_fernet_key = load_keys_and_salt(filename)
    derived_key = derive_key_from_password(master_password, salt)
    decrypted_fernet_key = decrypt_fernet_key(encrypted_fernet_key, private_key)

    if decrypted_fernet_key is None:
        print("Authentication failed.")
        return

    encrypted_data = load_data(filename)

    if not encrypted_data:
        print("No passwords stored yet.")
        return

    passwords = encrypted_data.split(b"||") #split using delimiter

    for encrypted_pair in passwords:
        decrypted_pair = decrypt_data(encrypted_pair, decrypted_fernet_key)
        if decrypted_pair: #check if decryption was successful
            website, password = decrypted_pair.decode().split(":")
            if website == website_to_find:
                print(f"Password for {website}: {password}")
                return

    print(f"Password for {website_to_find} not found.")

def main():
    """Main function to run the password manager."""
    filename = "passwords.dat"  # Store data in a file

    # Load or generate keys and salt
    load_keys_and_salt(filename)

    master_password = getpass.getpass("Enter your master password: ")

    while True:
        print("\nSecure Password Manager Menu:")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            add_password(filename, master_password)
        elif choice == '2':
            retrieve_password(filename, master_password)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
