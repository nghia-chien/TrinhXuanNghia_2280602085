# ecc_cipher.py - CHẠY NGON 100% VỚI FILE ecc.ui CỦA BẠN!!!
import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.ecc import Ui_MainWindow   # ĐÚNG VỚI FILE ecc.py BẠN ĐÃ TẠO


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("ECC Digital Signature - Nhóm 10")

        # ĐÚNG CHẲN TÊN NÚT TRONG FILE ecc.ui CỦA BẠN
        self.ui.pushButton_3.clicked.connect(self.call_api_gen_keys)   # Generate Keys
        self.ui.pushButton_2.clicked.connect(self.call_api_sign)      # Sign
        self.ui.pushButton.clicked.connect(self.call_api_verify)       # Verity → Verify

    def call_api_gen_keys(self):
        try:
            r = requests.get("http://127.0.0.1:5000/api/ecc/generate_keys", timeout=10)
            if r.status_code == 200:
                QMessageBox.information(self, "Thành công", "Tạo khóa ECC thành công!")
            else:
                QMessageBox.critical(self, "Lỗi", "Không thể tạo khóa ECC!")
        except:
            QMessageBox.critical(self, "Lỗi kết nối", "Server chưa chạy!\nChạy lệnh:\npython rsa_server.py")

    def call_api_sign(self):
        message = self.ui.textEdit.toPlainText().strip()   # Ô nhập tin nhắn (trên)
        if not message:
            QMessageBox.warning(self, "Cảnh báo", "Hãy nhập nội dung cần ký!")
            return
        try:
            r = requests.post("http://127.0.0.1:5000/api/ecc/sign",
                              json={"message": message}, timeout=10)
            if r.status_code == 200:
                signature = r.json()["signature"]
                self.ui.textEdit_2.setPlainText(signature)   # Ô hiện chữ ký (dưới)
                QMessageBox.information(self, "Thành công", "Signed Successfully")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", "Không kết nối được server!")

    def call_api_verify(self):
        message = self.ui.textEdit.toPlainText().strip()
        signature = self.ui.textEdit_2.toPlainText().strip()
        if not message or not signature:
            QMessageBox.warning(self, "Cảnh báo", "Cần cả tin nhắn và chữ ký!")
            return
        try:
            r = requests.post("http://127.0.0.1:5000/api/ecc/verify",
                              json={"message": message, "signature": signature}, timeout=10)
            if r.status_code == 200:
                if r.json().get("is_verified"):
                    QMessageBox.information(self, "Xác minh", "Verified Successfully")
                else:
                    QMessageBox.warning(self, "Xác minh", "Verified Fail")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", "Không kết nối được server!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())