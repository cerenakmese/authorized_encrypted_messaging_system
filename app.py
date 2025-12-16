from flask import Flask, render_template, request, jsonify, session
from encryption import MultiAlgoCrypto
from db import DBManager
from user import UserManager
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY","this the default key, change it!")  

crypto = MultiAlgoCrypto()
db = DBManager()
user_manager = UserManager()

@app.route('/')
def index():
    user_in_session= session.get('username')
    return render_template('index.html', user=user_in_session)

@app.route('/api/register', methods=['POST'])
def register():
    """Yeni kullanıcı kaydeder."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'User') 

    if not username or not password:
        return jsonify({"success": False, "error": "Kullanıcı adı ve şifre zorunludur!"})

    success, message = user_manager.register_user(username, password, role)
    return jsonify({"success": success, "message": message})

@app.route('/api/login', methods=['POST'])
def login():
    """Kullanıcı girişi yapar ve SESSION başlatır."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    success, message, role = user_manager.login_user(username, password)

    if success:
        # OTURUM BAŞLATMA (En Önemli Kısım)
        session['username'] = username
        session['role'] = role
        session['logged_in'] = True
        return jsonify({"success": True, "message": message, "role": role})
    else:
        return jsonify({"success": False, "error": message})

@app.route('/api/logout', methods=['POST'])
def logout():
    """Oturumu kapatır."""
    session.clear()
    return jsonify({"success": True, "message": "Çıkış yapıldı."})

@app.route('/api/check_session', methods=['GET'])
def check_session():
    """Frontend'in kullanıcının hala içeride olup olmadığını anlaması için."""
    if 'logged_in' in session:
        return jsonify({"logged_in": True, "username": session['username'], "role": session['role']})
    else:
        return jsonify({"logged_in": False})


@app.route('/send_message', methods=['POST'])
def send_message():
    """
    SADECE GİRİŞ YAPMIŞ kullanıcılar mesaj atabilir.
    Kullanıcı bilgisi artık 'request'ten değil, güvenli 'session'dan alınır.
    """
    if 'logged_in' not in session:
        return jsonify({"success": False, "error": "Önce giriş yapmalısınız!"}), 401

    data = request.json
    message_text = data.get('message')

    if not message_text:
        return jsonify({"success": False, "error": "Mesaj boş olamaz!"})

    # Oturumdaki bilgiler (İsim buradan alınıyor, bu yüzden 'null' olmaz)
    username = session['username']
    role = session['role']

    # 1. Şifrele
    encrypted_package = crypto.encrypt_message(message_text)

    # 2. Kaydet
    success = db.save_message(username, role, encrypted_package)

    if success:
        return jsonify({"success": True, "info": f"Mesaj {encrypted_package['algo']} ile şifrelendi."})
    else:
        return jsonify({"success": False, "error": "Veritabanı hatası!"})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    
    current_role = session.get('role','User')
    
    raw_messages = db.get_all_messages()
    processed_messages = []

    for msg in raw_messages:
       
        encrypted_content = msg['content']
        
        if current_role in ['Admin', 'Manager']:
            decrypted_text = crypto.decrypt_message(encrypted_content)
            display_text = decrypted_text 
            status = "decrypted"
        else:
            display_text = encrypted_content['ciphertext'] 
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