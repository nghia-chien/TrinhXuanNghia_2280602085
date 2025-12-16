# File: D:\lab02\lab-03\cipher\rsa\rsa_cipher.py
# CHỈ DÀNH CHO SERVER – KHÔNG ĐƯỢC IMPORT GUI!!!

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cipher.ecc import ECCCipher
class RSACipher:
    def __init__(self, key_size=2048, keys_dir="keys"):
        self.key_size = key_size
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(keys_dir, "public_key.pem")
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)

        print("Tạo khóa RSA thành công!")
        print(f"Private key: {self.private_key_path}")
        print(f"Public key : {self.public_key_path}")

    def load_keys(self):
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            print("Không tìm thấy khóa → Tự động tạo mới...")
            self.generate_keys()

        with open(self.private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(self.public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        return private_key, public_key

    def encrypt(self, message: str, public_key):
        data = message.encode('utf-8')
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plaintext.decode('utf-8')

    def sign(self, message: str, private_key):
        data = message.encode('utf-8')
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def verify(self, message: str, signature: bytes, public_key):
        try:
            data = message.encode('utf-8')
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except:
            return False
        # File: D:\lab02\lab-03\cipher\rsa\rsa_cipher.py
# CHỈ DÀNH CHO SERVER – KHÔNG ĐƯỢC IMPORT GUI!!!

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cipher.ecc import ECCCipher
class RSACipher:
    def __init__(self, key_size=2048, keys_dir="keys"):
        self.key_size = key_size
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(keys_dir, "public_key.pem")
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)

        print("Tạo khóa RSA thành công!")
        print(f"Private key: {self.private_key_path}")
        print(f"Public key : {self.public_key_path}")

    def load_keys(self):
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            print("Không tìm thấy khóa → Tự động tạo mới...")
            self.generate_keys()

        with open(self.private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(self.public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        return private_key, public_key

    def encrypt(self, message: str, public_key):
        data = message.encode('utf-8')
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plaintext.decode('utf-8')

    def sign(self, message: str, private_key):
        data = message.encode('utf-8')
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def verify(self, message: str, signature: bytes, public_key):
        try:
            data = message.encode('utf-8')
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except:
            return False# File: D:\lab02\lab-03\cipher\rsa\rsa_cipher.py
# CHỈ DÀNH CHO SERVER – KHÔNG ĐƯỢC IMPORT GUI!!!

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cipher.ecc import ECCCipher
class RSACipher:
    def __init__(self, key_size=2048, keys_dir="keys"):
        self.key_size = key_size
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(keys_dir, "public_key.pem")
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)

        print("Tạo khóa RSA thành công!")
        print(f"Private key: {self.private_key_path}")
        print(f"Public key : {self.public_key_path}")

    def load_keys(self):
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            print("Không tìm thấy khóa → Tự động tạo mới...")
            self.generate_keys()

        with open(self.private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(self.public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        return private_key, public_key

    def encrypt(self, message: str, public_key):
        data = message.encode('utf-8')
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plaintext.decode('utf-8')

    def sign(self, message: str, private_key):
        data = message.encode('utf-8')
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def verify(self, message: str, signature: bytes, public_key):
        try:
            data = message.encode('utf-8')
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except:
            return False