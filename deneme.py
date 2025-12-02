import os
import json
import base64
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

class MultiAlgoCrypto:
    def __init__(self):
        """
        Sistem başlatıldığında 3 farklı algoritma için güvenli anahtarlar üretilir.
        NOT: Gerçek hayatta bu anahtarlar veritabanından veya .env dosyasından okunmalıdır.
        Şimdilik her çalıştırmada yeni anahtar üretiyoruz.
        """
        # 1. Algoritma: Fernet (AES-128-CBC + HMAC)
        self.key_fernet = Fernet.generate_key()
        self.fernet = Fernet(self.key_fernet)

        # 2. Algoritma: AES-256-GCM
        # AESGCM için 256-bit (32 byte) anahtar üret
        self.key_aes = AESGCM.generate_key(bit_length=256)
        self.aes = AESGCM(self.key_aes)

        # 3. Algoritma: ChaCha20-Poly1305
        # ChaCha20 için 256-bit (32 byte) anahtar üret
        self.key_chacha = ChaCha20Poly1305.generate_key()
        self.chacha = ChaCha20Poly1305(self.key_chacha)

        print("--- GÜVENLİK SİSTEMİ BAŞLATILDI ---")
        print(f"[INFO] Fernet Key yüklendi.")
        print(f"[INFO] AES-GCM Key yüklendi.")
        print(f"[INFO] ChaCha20 Key yüklendi.")
        print("-------------------------------------")

    def _b64_encode(self, data_bytes):
        """Byte verisini string olarak saklamak için Base64'e çevirir."""
        return base64.b64encode(data_bytes).decode('utf-8')

    def _b64_decode(self, data_string):
        """Base64 string'i tekrar byte verisine çevirir."""
        return base64.b64decode(data_string.encode('utf-8'))

    def encrypt_message(self, plaintext):
        """
        Gelen metni RASTGELE bir algoritma seçerek şifreler.
        Geriye sadece şifreli metni değil, hangi algoritmanın kullanıldığını
        ve gerekli ek parametreleri (nonce/iv) içeren bir SÖZLÜK (dict) döner.
        """
        algorithms = ['FERNET', 'AES-GCM', 'CHACHA20']
        selected_algo = random.choice(algorithms)
        
        data_bytes = plaintext.encode('utf-8')
        result = {}

        if selected_algo == 'FERNET':
            # Fernet kendi içinde IV ve HMAC yönetir, ekstra nonce'a gerek yok
            token = self.fernet.encrypt(data_bytes)
            result = {
                'algo': 'FERNET',
                'ciphertext': self._b64_encode(token),
                'nonce': None # Fernet için gerekmez
            }

        elif selected_algo == 'AES-GCM':
            # AES-GCM için her seferinde benzersiz bir Nonce (IV) üretmeliyiz (12 byte)
            nonce = os.urandom(12)
            ciphertext = self.aes.encrypt(nonce, data_bytes, None)
            result = {
                'algo': 'AES-GCM',
                'ciphertext': self._b64_encode(ciphertext),
                'nonce': self._b64_encode(nonce) # Şifreyi açmak için bu nonce lazım!
            }

        elif selected_algo == 'CHACHA20':
            # ChaCha20 için de 12 byte Nonce gerekir
            nonce = os.urandom(12)
            ciphertext = self.chacha.encrypt(nonce, data_bytes, None)
            result = {
                'algo': 'CHACHA20',
                'ciphertext': self._b64_encode(ciphertext),
                'nonce': self._b64_encode(nonce)
            }

        print(f"[LOG] Mesaj '{selected_algo}' algoritması ile şifrelendi.")
        return result

    def decrypt_message(self, encrypted_package):
        """
        Şifreli paketi alır (dict), içindeki 'algo' bilgisine bakar
        ve doğru anahtarı/yöntemi kullanarak şifreyi çözer.
        """
        algo = encrypted_package.get('algo')
        ciphertext = self._b64_decode(encrypted_package.get('ciphertext'))
        
        try:
            if algo == 'FERNET':
                decrypted_bytes = self.fernet.decrypt(ciphertext)
            
            elif algo == 'AES-GCM':
                nonce = self._b64_decode(encrypted_package.get('nonce'))
                decrypted_bytes = self.aes.decrypt(nonce, ciphertext, None)
            
            elif algo == 'CHACHA20':
                nonce = self._b64_decode(encrypted_package.get('nonce'))
                decrypted_bytes = self.chacha.decrypt(nonce, ciphertext, None)
            
            else:
                return "HATA: Bilinmeyen algoritma!"

            return decrypted_bytes.decode('utf-8')
        
        except Exception as e:
            return f"GÜVENLİK HATASI: Şifre çözülemedi! Veri bozulmuş veya anahtar yanlış. ({str(e)})"

# --- TEST KISMI ---
if __name__ == "__main__":
    # 1. Sistemi başlat
    manager = MultiAlgoCrypto()

    # 2. Gönderilecek gizli mesaj
    mesaj = "CENG472 dersi için çok gizli proje notları!"
    print(f"\nOrijinal Mesaj: {mesaj}\n")

    sifreli_paket = manager.encrypt_message(mesaj)
        
        
    print(f"DB'ye Kaydedilen Paket: {sifreli_paket}")
        
    
    cozulen_mesaj = manager.decrypt_message(sifreli_paket)
    print(f"Çözülen Mesaj: {cozulen_mesaj}\n")
