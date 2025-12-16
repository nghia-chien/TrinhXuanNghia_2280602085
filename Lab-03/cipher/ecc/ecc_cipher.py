# cipher/ecc/ecc_cipher.py
import os
import ecdsa
from ecdsa import SigningKey, VerifyingKey, NIST256p


class ECCCipher:
    def __init__(self, keys_dir="cipher/ecc/keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)
        self.private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(self.keys_dir, "public_key.pem")

    def generate_keys(self):
        """Tạo cặp khóa ECC NIST P-256 và lưu dưới dạng PEM"""
        sk = SigningKey.generate(curve=NIST256p)      # Private key
        vk = sk.verifying_key                          # Public key

        # Lưu private key
        with open(self.private_key_path, "wb") as f:
            f.write(sk.to_pem())

        # Lưu public key
        with open(self.public_key_path, "wb") as f:
            f.write(vk.to_pem())

        print("ECC: Tạo khóa thành công!")
        print(f"   Private key  → {self.private_key_path}")
        print(f"   Public key   → {self.public_key_path}")

    def load_keys(self):
        """Load khóa từ file, nếu chưa có thì tự động tạo mới"""
        if not os.path.exists(self.private_key_path) or not os.path.exists(self.public_key_path):
            print("ECC: Không tìm thấy khóa → đang tạo mới...")
            self.generate_keys()

        with open(self.private_key_path, "rb") as f:
            sk = SigningKey.from_pem(f.read())

        with open(self.public_key_path, "rb") as f:
            vk = VerifyingKey.from_pem(f.read())

        return sk, vk

    def sign(self, message: str) -> str:
        """Ký tin nhắn bằng private key → trả về hex"""
        sk, _ = self.load_keys()
        signature = sk.sign(message.encode("utf-8"))
        return signature.hex()          # dễ truyền JSON

    def verify(self, message: str, signature_hex: str) -> bool:
        """Xác minh chữ ký → trả về True/False"""
        _, vk = self.load_keys()
        try:
            signature_bytes = bytes.fromhex(signature_hex)
            vk.verify(signature_bytes, message.encode("utf-8"))
            return True
        except ecdsa.BadSignatureError:
            return False
        except Exception as e:
            print(f"Lỗi verify ECC: {e}")
            return False