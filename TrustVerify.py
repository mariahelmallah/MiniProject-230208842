import hashlib
import os
import json
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

FOLDER_PATH = "Test Files"
METADATA_FILE = "metadata.json"
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
SIGNATURE_FILE = "signature.sig"


def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def get_metadata_hash_bytes():
    metadata_path = os.path.join(FOLDER_PATH, METADATA_FILE)

    if not os.path.exists(metadata_path):
        print("metadata.json not found!")
        return None

    sha256 = hashlib.sha256()

    with open(metadata_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.digest()


def create_manifest(folder_path):
    metadata = {}

    for file_name in os.listdir(folder_path):
        if file_name == METADATA_FILE:
            continue

        file_path = os.path.join(folder_path, file_name)

        if os.path.isfile(file_path):
            file_hash = calculate_file_hash(file_path)
            metadata[file_name] = file_hash

    metadata_path = os.path.join(folder_path, METADATA_FILE)

    with open(metadata_path, "w") as json_file:
        json.dump(metadata, json_file, indent=4)

    print("metadata.json has been created successfully!")


def check_files(folder_path):
    metadata_path = os.path.join(folder_path, METADATA_FILE)

    if not os.path.exists(metadata_path):
        print("metadata.json not found!")
        return

    with open(metadata_path, "r") as json_file:
        old_metadata = json.load(json_file)

    current_metadata = {}

    for file_name in os.listdir(folder_path):
        if file_name == METADATA_FILE:
            continue

        file_path = os.path.join(folder_path, file_name)

        if os.path.isfile(file_path):
            current_metadata[file_name] = calculate_file_hash(file_path)

    for file_name, old_hash in old_metadata.items():
        if file_name not in current_metadata:
            print(file_name, "-> DELETED")
        elif current_metadata[file_name] == old_hash:
            print(file_name, "-> OK")
        else:
            print(file_name, "-> MODIFIED")

    for file_name in current_metadata:
        if file_name not in old_metadata:
            print(file_name, "-> NEW FILE")


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Keys generated successfully!")


def sign_manifest():
    if not os.path.exists(PRIVATE_KEY_FILE):
        print("private_key.pem not found!")
        return

    metadata_hash = get_metadata_hash_bytes()
    if metadata_hash is None:
        return

    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature = private_key.sign(
        metadata_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(SIGNATURE_FILE, "wb") as sig_file:
        sig_file.write(signature)

    print("metadata.json hash has been signed successfully!")


def verify_signature():
    if not os.path.exists(PUBLIC_KEY_FILE):
        print("public_key.pem not found!")
        return

    if not os.path.exists(SIGNATURE_FILE):
        print("signature.sig not found!")
        return

    metadata_hash = get_metadata_hash_bytes()
    if metadata_hash is None:
        return

    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    with open(SIGNATURE_FILE, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            metadata_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Verification Succeeded")
    except Exception:
        print("Verification Failed")


def print_usage():
    print("Usage:")
    print("  python TrustVerify.py manifest")
    print("  python TrustVerify.py check")
    print("  python TrustVerify.py genkeys")
    print("  python TrustVerify.py sign")
    print("  python TrustVerify.py verify")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_usage()
    else:
        command = sys.argv[1].lower()

        if command == "manifest":
            create_manifest(FOLDER_PATH)
        elif command == "check":
            check_files(FOLDER_PATH)
        elif command == "genkeys":
            generate_keys()
        elif command == "sign":
            sign_manifest()
        elif command == "verify":
            verify_signature()
        else:
            print("Unknown command!")
            print_usage()