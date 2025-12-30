import os
import datetime
from pymongo import MongoClient, errors
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class DBManager:
    def __init__(self):
  
        uri = os.getenv("MONGO_URI")
        if not uri:
            raise ValueError("HATA: MONGO_URI bulunamadı! Lütfen .env dosyasını kontrol edin.")

        try:
            self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            self.db = self.client["SecureChatDB"]
            self.messages_collection = self.db["messages"]
            
            self.client.server_info()
            print("[INFO] MongoDB bağlantısı BAŞARILI.")
            
        except errors.ServerSelectionTimeoutError:
            print("[HATA] MongoDB'ye bağlanılamadı! İnternet bağlantınızı veya URI adresini kontrol edin.")
            self.client = None

    def save_message(self, username, user_role, encrypted_package, allowed_roles):

        if not self.client:
            print("[HATA] Veritabanı bağlantısı yok, kayıt yapılamadı.")
            return False

        document = {
            "sender": username,
            "role": user_role,
            "allowed_roles": allowed_roles,
            "timestamp": datetime.datetime.now(), 
            "content": encrypted_package 
        }

        try:
            result = self.messages_collection.insert_one(document)
            print(f"[LOG] Mesaj başarıyla kaydedildi. ID: {result.inserted_id}")
            return True
        except Exception as e:
            print(f"[HATA] Kayıt sırasında hata oluştu: {e}")
            return False

    def get_all_messages(self):
        
        if not self.client:
            return []
        
        return list(self.messages_collection.find().sort("timestamp", -1))


