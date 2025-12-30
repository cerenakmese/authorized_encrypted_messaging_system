import os
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # XSS temizliği için
from encryption import MultiAlgoCrypto
from db import DBManager
from user import UserManager
from dotenv import load_dotenv

# .env yükle
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli_anahtar_34")
app.permanent_session_lifetime = timedelta(minutes=30)

# Güvenlik: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Sınıfları Başlat
crypto = MultiAlgoCrypto()
db = DBManager()
user_manager = UserManager()


# =========================================================
# 1. ÇOK SAYFALI YÖNLENDİRMELER (ROUTING)
# =========================================================

@app.route('/')
def root():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    # ARTIK index.html DEĞİL, login.html DÖNÜYOR
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))
    # ARTIK index.html DEĞİL, dashboard.html DÖNÜYOR
    return render_template('dashboard.html', user=session.get('username'), role=session.get('role'))


@app.route('/admin')
def admin_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') != 'Admin':
        return render_template('403.html'), 403
    return render_template('admin.html')


@app.route('/403')
def access_denied():
    return render_template('403.html')


# =========================================================
# 2. API ENDPOINTLERİ
# =========================================================

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    success, message, role = user_manager.login_user(data.get('username'), data.get('password'))
    if success:
        session.permanent = True
        session['username'] = data.get('username')
        session['role'] = role
        session['logged_in'] = True
        return jsonify({"success": True, "redirect_url": "/dashboard"})
    return jsonify({"success": False, "error": message}), 401


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    success, message = user_manager.register_user(data.get('username'), data.get('password'), data.get('role', 'User'))
    return jsonify({"success": success, "message": message, "error": message if not success else None})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True, "redirect_url": "/login"})


@app.route('/api/check_session', methods=['GET'])
def check_session():
    if 'logged_in' in session:
        return jsonify({"logged_in": True, "username": session['username'], "role": session['role']})
    return jsonify({"logged_in": False})


# =========================================================
# 3. MESAJLAŞMA (Rol Seçimi Mantığı Burada)
# =========================================================

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'logged_in' not in session:
        return jsonify({"success": False, "error": "Oturum yok!"}), 401

    data = request.json
    raw_msg = bleach.clean(data.get('message', ''))

    # FRONTEND'DEN GELEN HEDEF ROLLER (Ceren/Sena Mantığı)
    allowed_roles = data.get('allowed_roles', [])

    if not raw_msg:
        return jsonify({"success": False, "error": "Boş mesaj gönderilemez!"})

    if not allowed_roles:
        return jsonify({"success": False, "error": "En az bir hedef kitle (Rol) seçmelisin!"})

    # Şifrele ve Kaydet
    try:
        encrypted_package = crypto.encrypt_message(raw_msg)
        # allowed_roles veritabanına kaydediliyor
        db.save_message(session['username'], session['role'], encrypted_package, allowed_roles)
        return jsonify({"success": True, "info": f"Mesaj {encrypted_package['algo']} ile şifrelendi."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'logged_in' not in session:
        return jsonify([])

    current_role = session.get('role', 'User')
    current_user = session.get('username')

    messages = db.get_all_messages()
    processed = []

    for msg in messages:
        # DB'den gelen izinli roller listesi
        target_roles = msg.get('allowed_roles', [])

        # YETKİ KONTROLÜ:
        # 1. Benim rolüm listede var mı? VEYA
        # 2. Mesajı ben mi attım?
        can_decrypt = (current_role in target_roles) or (msg['sender'] == current_user)

        decrypted_text = None
        if can_decrypt:
            try:
                decrypted_text = crypto.decrypt_message(msg['content'])
            except:
                decrypted_text = "HATA"

        processed.append({
            "sender": msg['sender'],
            "role": msg['role'],
            "timestamp": msg['timestamp'].strftime("%H:%M") if msg.get('timestamp') else "--:--",
            "algo": msg['content']['algo'],
            "ciphertext": msg['content']['ciphertext'],
            "plaintext": decrypted_text,
            "can_decrypt": can_decrypt,
            "targets": target_roles  # Frontend'de göstermek için
        })

    return jsonify(processed)


if __name__ == '__main__':
    app.run(debug=True, port=5000)