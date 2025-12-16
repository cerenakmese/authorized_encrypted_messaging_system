import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class UserManager:
    def __init__(self):
        uri = os.getenv("MONGO_URI")
        if not uri:
            print("[HATA] UserManager veritabanına bağlanamadı!")
            return

        self.client = MongoClient(uri)
        self.db = self.client["SecureChatDB"]
        self.users_collection = self.db["users"]

    def register_user(self, username, password, role="User"):
        
        if self.users_collection.find_one({"username": username}):
            return False, "Bu kullanıcı adı zaten alınmış."

        hashed_password = generate_password_hash(password)

        user_data = {
            "username": username,
            "password_hash": hashed_password, 
            "role": role
        }

        try:
            self.users_collection.insert_one(user_data)
            print(f"[KAYIT] Yeni kullanıcı oluşturuldu: {username} ({role})")
            return True, "Kayıt başarılı!"
        except Exception as e:
            return False, f"Veritabanı hatası: {e}"

    def login_user(self, username, password):
       
        user = self.users_collection.find_one({"username": username})

        if not user:
            return False, "Kullanıcı bulunamadı.", None

        if check_password_hash(user['password_hash'], password):
            print(f"[GİRİŞ] {username} sisteme girdi.")
    
            return True, "Giriş başarılı.", user['role']
        else:
            return False, "Hatalı parola!", None


if __name__ == "__main__":
    # Test için çalıştırılabilir kısım
    manager = UserManager()
    
    # 1. Kayıt Testi (Admin oluştur)
    # İlk çalıştırmada bunu kaydeder, sonrakilerde "zaten var" der.
    basari, mesaj = manager.register_user("admin_ceren", "gizlisifre123", "Admin")
    print(f"Kayıt Sonucu: {mesaj}")

    # 2. Giriş Testi (Doğru şifre)
    login_success, login_msg, role = manager.login_user("admin_ceren", "gizlisifre123")
    print(f"Giriş Denemesi (Doğru): {login_msg} - Rol: {role}")

    # 3. Giriş Testi (Yanlış şifre)
    login_success, login_msg, role = manager.login_user("admin_ceren", "yanlissifre")
    print(f"Giriş Denemesi (Yanlış): {login_msg}")