import os
import datetime
from pymongo import MongoClient, errors
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class DBManager:
    def __init__(self):
        """
        MongoDB bağlantısını başlatır.
        Bağlantı adresi (URI) kodun içinde değil, .env dosyasında saklanmalıdır.
        """
        uri = os.getenv("MONGO_URI")
        if not uri:
            raise ValueError("HATA: MONGO_URI bulunamadı! Lütfen .env dosyasını kontrol edin.")

        try:
            # Bağlantıyı kur
            self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            
            # Veritabanını ve Koleksiyonu Seç
            # Veritabanı adı: SecureChatDB
            self.db = self.client["SecureChatDB"]
            
            # Mesajların tutulacağı tablo (collection): messages
            self.messages_collection = self.db["messages"]
            
            # Bağlantıyı test et
            self.client.server_info()
            print("[INFO] MongoDB bağlantısı BAŞARILI.")
            
        except errors.ServerSelectionTimeoutError:
            print("[HATA] MongoDB'ye bağlanılamadı! İnternet bağlantınızı veya URI adresini kontrol edin.")
            self.client = None

    def save_message(self, username, user_role, encrypted_package):
        """
        Şifreli mesaj paketini veritabanına kaydeder.
        
        Args:
            username (str): Gönderen kullanıcının adı
            user_role (str): Gönderen kullanıcının rolü (Admin, User vb.)
            encrypted_package (dict): crypto_manager'dan gelen şifreli veri {algo, ciphertext, nonce}
        """
        if not self.client:
            print("[HATA] Veritabanı bağlantısı yok, kayıt yapılamadı.")
            return False

        # Proje belgesinde istenen "Timestamp" ve "Identity" bilgilerini ekliyoruz
        document = {
            "sender": username,
            "role": user_role,
            "timestamp": datetime.datetime.now(), # Zaman damgası (Doğrulanabilirlik için)
            "content": encrypted_package # Şifreli veri bloğu
        }

        try:
            result = self.messages_collection.insert_one(document)
            print(f"[LOG] Mesaj başarıyla kaydedildi. ID: {result.inserted_id}")
            return True
        except Exception as e:
            print(f"[HATA] Kayıt sırasında hata oluştu: {e}")
            return False

    def get_all_messages(self):
        """
        Test amaçlı: Tüm mesajları getirir.
        Gerçek uygulamada burada rol kontrolü (Access Control) yapılacaktır.
        """
        if not self.client:
            return []
        
        # En yeniden en eskiye doğru sırala
        return list(self.messages_collection.find().sort("timestamp", -1))

# --- TEST KISMI ---
if __name__ == "__main__":
    # Test için dummy (sahte) veri kullanalım
    print("--- DB TEST BAŞLIYOR ---")
    
    # NOT: Bu kodu çalıştırmadan önce .env dosyasını oluşturmalısınız!
    try:
        db = DBManager()
        
        # Örnek bir şifreli paket (crypto_manager'dan gelmiş gibi)
        sahte_sifreli_paket = {
            "algo": "AES-GCM",
            "ciphertext": "aGVsbG8gd29ybGQ=", # Base64 örnek
            "nonce": "MTIzNDU2Nzg5MDEy"      # Base64 örnek
        }
        
        # Kaydetmeyi dene
        db.save_message("Sadık Emre", "Student", sahte_sifreli_paket)
        
        # Okumayı dene
        mesajlar = db.get_all_messages()
        print(f"\nVeritabanındaki Toplam Mesaj Sayısı: {len(mesajlar)}")
        
    except ValueError as ve:
        print(ve)