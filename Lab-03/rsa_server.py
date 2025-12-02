# rsa_server.py - HOÀN CHỈNH 100%: CÓ CẢ RSA + ECC
from flask import Flask, request, jsonify
from cipher.rsa.rsa_cipher import RSACipher
from cipher.ecc.ecc_cipher import ECCCipher   # Đảm bảo bạn có file này

app = Flask(__name__)

# Khởi tạo cả 2 cipher
rsa_cipher = RSACipher()
ecc_cipher = ECCCipher()   # Đây là cái bạn đang thiếu!


# ========================= RSA =========================
@app.route("/api/rsa/generate_keys", methods=["GET"])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({"message": "RSA keys generated successfully"})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json
    message = data.get("message")
    key_type = data.get("key_type", "public")
    private_key, public_key = rsa_cipher.load_keys()
    key = public_key if key_type == "public" else private_key
    ciphertext = rsa_cipher.encrypt(message, key)
    return jsonify({"encrypted_message": ciphertext.hex()})

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json
    cipher_hex = data.get("cipher_text")
    key_type = data.get("key_type", "private")
    private_key, public_key = rsa_cipher.load_keys()
    key = private_key if key_type == "private" else public_key
    try:
        ciphertext_bytes = bytes.fromhex(cipher_hex)
        decrypted = rsa_cipher.decrypt(ciphertext_bytes, key)
        return jsonify({"decrypted_message": decrypted})
    except:
        return jsonify({"error": "Decrypt failed"}), 400

@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign_message():
    data = request.json
    message = data.get("message")
    private_key, _ = rsa_cipher.load_keys()
    signature = rsa_cipher.sign(message, private_key)
    return jsonify({"signature": signature.hex()})

@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify_signature():
    data = request.json
    message = data.get("message")
    signature_hex = data.get("signature")
    _, public_key = rsa_cipher.load_keys()
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature_bytes, public_key)
        return jsonify({"is_verified": is_verified})
    except:
        return jsonify({"is_verified": False})


# ========================= ECC =========================
@app.route("/api/ecc/generate_keys", methods=["GET"])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({"message": "ECC keys generated successfully!"})

@app.route("/api/ecc/sign", methods=["POST"])
def ecc_sign():
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Missing message"}), 400
    signature = ecc_cipher.sign(message)           # đã trả về hex trong class
    return jsonify({"signature": signature})

@app.route("/api/ecc/verify", methods=["POST"])
def ecc_verify():
    data = request.get_json()
    message = data.get("message", "")
    signature_hex = data.get("signature", "")
    if not message or not signature_hex:
        return jsonify({"error": "Missing data"}), 400
    is_valid = ecc_cipher.verify(message, signature_hex)
    return jsonify({"is_verified": is_valid})


# ========================= RUN =========================
if __name__ == "__main__":
    print("Server đang chạy tại http://127.0.0.1:5000")
    print("API RSA và ECC đều đã sẵn sàng!")
    app.run(host="0.0.0.0", port=5000, debug=True)