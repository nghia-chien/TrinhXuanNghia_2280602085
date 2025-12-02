import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.caesar import Ui_MainWindow
import requests

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # map đúng tên widget trong UI
        self.ui.pushButton.clicked.connect(self.call_api_encrypt)       # btn encrypt
        self.ui.pushButton_2.clicked.connect(self.call_api_decrypt)    # btn decrypt

    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/encrypt"

        payload = {
            "plain_text": self.ui.textEdit_2.toPlainText(),   # plain text
            "key": self.ui.textEdit_4.toPlainText()           # key
        }

        try:
            response = requests.post(url, json=payload)

            if response.status_code == 200:
                data = response.json()
                self.ui.textEdit_3.setText(data["encrypted_message"])  # cipher text

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Successfully")
                msg.exec_()
            else:
                print("Error:", response.text)

        except requests.exceptions.RequestException as e:
            print("Request error:", e)

    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/decrypt"

        payload = {
            "cipher_text": self.ui.textEdit_3.toPlainText(),  # cipher text
            "key": self.ui.textEdit_4.toPlainText()           # key
        }

        try:
            response = requests.post(url, json=payload)

            if response.status_code == 200:
                data = response.json()
                self.ui.textEdit_2.setText(data["decrypted_message"])  # plain text

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Successfully")
                msg.exec_()
            else:
                print("Error:", response.text)

        except requests.exceptions.RequestException as e:
            print("Request error:", e)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MyApp()
    win.show()
    sys.exit(app.exec_())
