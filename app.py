from flask import Flask, render_template, request, jsonify
from deneme import MultiAlgoCrypto
from db import DBManager

app = Flask(__name__)

# Yöneticileri başlatalım
crypto = MultiAlgoCrypto()
db = DBManager()

@app.route('/')
def index():
    """Ana sayfa arayüzünü gösterir."""
    return render_template('index.html')

@app.route('/send_message', methods=['POST'])
def send_message():
    """Kullanıcıdan gelen mesajı şifreler ve DB'ye kaydeder."""
    data = request.json
    username = data.get('username')
    role = data.get('role')
    message = data.get('message')

    if not message:
        return jsonify({"success": False, "error": "Mesaj boş olamaz!"})

    # 1. Şifreleme Yöneticisi Rastgele Bir Algoritma Seçip Şifreler
    encrypted_package = crypto.encrypt_message(message)

    # 2. Veritabanı Yöneticisi Bunu Kaydeder
    success = db.save_message(username, role, encrypted_package)

    if success:
        return jsonify({"success": True, "info": f"Mesaj {encrypted_package['algo']} ile şifrelendi."})
    else:
        return jsonify({"success": False, "error": "Veritabanı hatası!"})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    """
    Mesajları listeler.
    Secure Coding Notu: Burada 'Access Control' (Yetki Kontrolü) simülasyonu yapıyoruz.
    Eğer 'current_user_role' parametresi 'Admin' değilse şifreyi çözmüyoruz.
    """
    # Arayüzden o anki kullanıcının rolünü alalım (Simülasyon)
    current_role = request.args.get('current_role', 'User')
    
    raw_messages = db.get_all_messages()
    processed_messages = []

    for msg in raw_messages:
        # Mesaj verisi
        encrypted_content = msg['content']
        
        # --- YETKİ KONTROLÜ (ACCESS CONTROL) ---
        # Sadece 'Admin' veya 'Manager' rolündekiler şifreyi çözülmüş görebilir.
        # Diğerleri sadece şifreli (anlamsız) metni görür.
        if current_role in ['Admin', 'Manager']:
            decrypted_text = crypto.decrypt_message(encrypted_content)
            display_text = decrypted_text # Açık hali
            status = "decrypted"
        else:
            display_text = encrypted_content['ciphertext'] # Şifreli hali
            status = "encrypted"

        processed_messages.append({
            "sender": msg['sender'],
            "role": msg['role'],
            "timestamp": msg['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
            "algo": encrypted_content['algo'],
            "text": display_text,
            "status": status
        })

    return jsonify(processed_messages)

if __name__ == '__main__':
    app.run(debug=True, port=5000)