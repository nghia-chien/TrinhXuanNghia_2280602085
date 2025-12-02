# File: D:\lab02\lab-03\main_rsa.py
import sys
import requests
from PyQt5 import QtWidgets
from ui.rsa import Ui_MainWindow

class RSAGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("RSA Cipher - Nhóm 10")

        # Kết nối các nút
        self.ui.pushButton.clicked.connect(self.generate_keys)      # Generate Keys
        self.ui.pushButton_3.clicked.connect(self.encrypt)       # Encrypt
        self.ui.pushButton_4.clicked.connect(self.decrypt)         # Decrypt
        self.ui.pushButton_5.clicked.connect(self.sign)            # Sign
        self.ui.pushButton_2.clicked.connect(self.verify)          # Verify

    def call_api_get(self, url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                self.ui.textEdit_4.setPlainText(f"Lỗi {response.status_code}: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            self.ui.textEdit_4.setPlainText(f"Không kết nối được server!\nLỗi: {e}\nChạy: python rsa_server.py")
            return None

    def call_api_post(self, url, payload):
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                self.ui.textEdit_4.setPlainText(f"Lỗi {response.status_code}: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            self.ui.textEdit_4.setPlainText(f"Không kết nối được server!\nLỗi: {e}")
            return None

    def generate_keys(self):
        data = self.call_api_get("http://127.0.0.1:5000/api/rsa/generate_keys")
        if data:
            self.ui.textEdit_4.setPlainText("Tạo khóa thành công!\nPrivate & Public key đã lưu trong thư mục keys/")

    def encrypt(self):
        message = self.ui.textEdit.toPlainText().strip()
        if not message:
            self.ui.textEdit_4.setPlainText("Nhập Plain Text trước!")
            return
        payload = {"message": message, "key_type": "public"}
        data = self.call_api_post("http://127.0.0.1:5000/api/rsa/encrypt", payload)
        if data and "encrypted_message" in data:
            self.ui.textEdit_2.setPlainText(data["encrypted_message"])
            self.ui.textEdit_4.setPlainText("Mã hóa thành công!")

    def decrypt(self):
        cipher_text = self.ui.textEdit_2.toPlainText().strip()
        if not cipher_text:
            self.ui.textEdit_4.setPlainText("Chưa có Cipher Text để giải mã!")
            return
        payload = {"cipher_text": cipher_text, "key_type": "private"}
        data = self.call_api_post("http://127.0.0.1:5000/api/rsa/decrypt", payload)
        if data and "decrypted_message" in data:
            self.ui.textEdit_3.setPlainText(data["decrypted_message"])
            self.ui.textEdit_4.setPlainText("Giải mã thành công!")

    def sign(self):
        message = self.ui.textEdit.toPlainText().strip()
        if not message:
            self.ui.textEdit_4.setPlainText("Nhập tin nhắn để ký!")
            return
        payload = {"message": message}
        data = self.call_api_post("http://127.0.0.1:5000/api/rsa/sign", payload)
        if data and "signature" in data:
            self.ui.textEdit_3.setPlainText(data["signature"])
            self.ui.textEdit_4.setPlainText("Đã ký số thành công!")

    def verify(self):
        message = self.ui.textEdit.toPlainText().strip()
        signature = self.ui.textEdit_3.toPlainText().strip()
        if not message or not signature:
            self.ui.textEdit_4.setPlainText("Cần cả tin nhắn và chữ ký!")
            return
        payload = {"message": message, "signature": signature}
        data = self.call_api_post("http://127.0.0.1:5000/api/rsa/verify", payload)
        if data and "is_verified" in data:
            result = "HỢP LỆ" if data["is_verified"] else "KHÔNG HỢP LỆ"
            self.ui.textEdit_4.setPlainText(f"Xác minh chữ ký: {result}")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = RSAGUI()
    window.show()
    sys.exit(app.exec_())