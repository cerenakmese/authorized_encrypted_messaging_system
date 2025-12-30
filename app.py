import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # XSS temizliği için
from encryption import MultiAlgoCrypto
from db import DBManager
from user import UserManager
from dotenv import load_dotenv

# .env yükle (Klasör yolunu garantiye alarak)
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

app = Flask(__name__)
# Güvenlik için secret key
app.secret_key = os.getenv("SECRET_KEY", "cok_gizli_anahtar_buraya_yazilacak")
# Oturum zaman aşımı (5 dk)
app.permanent_session_lifetime = timedelta(minutes=5)

# --- GÜVENLİK AYARI 1: RATE LIMITING (Brute-Force Koruması) ---
# Kullanıcıların IP adresine göre istekleri sınırlar.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"], # Genel sınırlar
    storage_uri="memory://"
)

# Yöneticileri başlatalım
crypto = MultiAlgoCrypto()
db = DBManager()
user_manager = UserManager()

@app.route('/')
def index():
    user_in_session = session.get('username')
    return render_template('index.html', user=user_in_session)

# --- AUTH (KİMLİK DOĞRULAMA) İŞLEMLERİ ---

@app.route('/api/register', methods=['POST'])
def register():
    """Yeni kullanıcı kaydeder."""
    data = request.json
    # XSS Koruması: Kullanıcı adını da temizleyelim
    username = bleach.clean(data.get('username', ''))
    password = data.get('password')
    role = data.get('role', 'User')

    if not username or not password:
        return jsonify({"success": False, "error": "Kullanıcı adı ve şifre zorunludur!"})

    success, message = user_manager.register_user(username, password, role)
    return jsonify({"success": success, "message": message})

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute") # <-- ÖZEL KORUMA: Dakikada en fazla 5 giriş denemesi!
def login():
    """Kullanıcı girişi yapar ve SESSION başlatır."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    success, message, role = user_manager.login_user(username, password)

    if success:
        # OTURUM BAŞLATMA
        session.permanent = True # 5 dk kuralı işlesin
        session['username'] = username
        session['role'] = role
        session['logged_in'] = True
        return jsonify({"success": True, "message": message, "role": role})
    else:
        return jsonify({"success": False, "error": message}), 401

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

# --- MESAJLAŞMA İŞLEMLERİ ---

@app.route('/send_message', methods=['POST'])
def send_message():
    # 1️⃣ Giriş kontrolü
    if 'logged_in' not in session:
        return jsonify({
            "success": False,
            "error": "Önce giriş yapmalısınız!"
        }), 401

    # 2️⃣ Frontend'den gelen veri
    data = request.json
    raw_message = data.get('message')
    allowed_roles = data.get('allowed_roles') # Örn: ['Admin', 'Manager']

    # 3️⃣ Validasyonlar
    if not raw_message:
        return jsonify({
            "success": False,
            "error": "Mesaj boş olamaz!"
        })

    if not allowed_roles or not isinstance(allowed_roles, list):
        # Varsayılan olarak herkese (veya sadece User'a) açabiliriz ama 
        # güvenli kodlamada 'fail-safe defaults' gereği hata dönmek daha iyidir.
        return jsonify({
            "success": False,
            "error": "En az bir hedef rol seçilmelidir!"
        })

    # --- GÜVENLİK AYARI 2: XSS TEMİZLİĞİ (Input Sanitization) ---
    # Kullanıcı <script>alert('hack')</script> yazsa bile temizler.
    clean_message = bleach.clean(raw_message)

    # 4️⃣ Session'dan güvenli bilgiler
    username = session['username']
    role = session['role']

    # 5️⃣ Mesajı şifrele
    encrypted_package = crypto.encrypt_message(clean_message)

    # 6️⃣ Veritabanına kaydet
    success = db.save_message(
        username,
        role,
        encrypted_package,
        allowed_roles  # 👈 Kimlerin görebileceği bilgisi DB'ye gidiyor
    )

    if success:
        return jsonify({
            "success": True,
            "info": f"Mesaj {encrypted_package['algo']} ile şifrelendi."
        })
    else:
        return jsonify({
            "success": False,
            "error": "Veritabanı hatası!"
        })

@app.route('/get_messages', methods=['GET'])
def get_messages():
    """
    Mesajları listeler.
    Şifre çözme yetkisi artık mesajın 'allowed_roles' listesiyle
    kullanıcının rolü eşleşiyor mu diye bakılarak belirlenir.
    """
    
    current_role = session.get('role', 'Visitor') # Giriş yapmamışsa Visitor
    
    raw_messages = db.get_all_messages()
    processed_messages = []

    for msg in raw_messages:
        encrypted_content = msg['content']
        # Mesajın izin verilen rolleri (Veritabanından gelir, yoksa boş liste)
        allowed_roles = msg.get('allowed_roles', [])
        
        # --- YENİ YETKİ KONTROLÜ (RBAC) ---
        # Kullanıcının rolü, mesajın izin listesinde var mı?
        # VEYA Gönderen kişi kendisi mi? (Kendi mesajını her zaman görebilmeli)
        sender_name = msg.get('sender')
        current_user = session.get('username')

        is_authorized = (current_role in allowed_roles) or (current_user == sender_name)
        
        if is_authorized:
            try:
                decrypted_text = crypto.decrypt_message(encrypted_content)
                display_text = decrypted_text
                status = "decrypted"
            except:
                display_text = "[Şifre Çözme Hatası]"
                status = "error"
        else:
            
            display_text = "🚫 BU MESAJI GÖRME YETKİNİZ YOK (GİZLİ İÇERİK)"
            status = "encrypted"

        processed_messages.append({
            "sender": sender_name,
            "role": msg.get('role', 'Unknown'),
            "timestamp": msg['timestamp'].strftime("%Y-%m-%d %H:%M:%S") if msg.get('timestamp') else "Tarih Yok",
            "algo": encrypted_content.get('algo', 'Unknown'),
            "text": display_text,
            "status": status,
            "target_roles": allowed_roles # Frontend'de göstermek istersen
        })

    return jsonify(processed_messages)

# Rate Limit hatası alanlar için özel mesaj
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"success": False, "error": "Çok fazla deneme yaptınız! Lütfen 1 dakika bekleyin."}), 429

if __name__ == '__main__':
    app.run(debug=True, port=5000)