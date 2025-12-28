import os
from pymongo import MongoClient
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

def clear_messages():
    uri = os.getenv("MONGO_URI")
    if not uri:
        print("HATA: .env dosyasında MONGO_URI bulunamadı!")
        return

    try:
        client = MongoClient(uri)
        db = client["SecureChatDB"]
        collection = db["messages"]

        # Tüm mesajları sil
        result = collection.delete_many({})
        
        print(f"✅ İŞLEM BAŞARILI!")
        print(f"Toplam {result.deleted_count} adet eski mesaj silindi.")
        print("Artık Gelen Kutusu tertemiz.")

    except Exception as e:
        print(f"HATA OLUŞTU: {e}")

if __name__ == "__main__":
    confirm = input("Tüm mesajları silmek istediğine emin misin? (e/h): ")
    if confirm.lower() == 'e':
        clear_messages()
    else:
        print("İşlem iptal edildi.")