import os
import base64
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, 
    ChaCha20Poly1305, 
    AESSIV
)

class MultiAlgoCrypto:
    def __init__(self):
        """
        Şifreleme anahtarlarını sabit bir dosyadan yönetir.
        Eğer anahtar dosyası yoksa ilk seferde oluşturur ve kaydeder.
        Böylece uygulama yeniden başlatılsa bile eski mesajlar çözülebilir.
        """
        self.key_file = "secret.keys"
        self._load_or_generate_keys()

        print("--- GÜVENLİK SİSTEMİ BAŞLATILDI ---")
        print(f"[INFO] 4 Algoritma Yüklendi: Fernet, AES-GCM, ChaCha20, AES-SIV")
        print(f"[INFO] Anahtarlar '{self.key_file}' dosyasından okundu.")
        print("-------------------------------------")

    def _load_or_generate_keys(self):
        """Anahtarları dosyadan okur, yoksa oluşturup kaydeder."""
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    content = f.read().splitlines()
                
                # Dosya içeriğini kontrol et (Artık 4 anahtar bekliyoruz)
                if len(content) >= 4:
                    self.key_fernet = content[0]
                    self.key_aes = content[1]
                    self.key_chacha = content[2]
                    self.key_siv = content[3]
                else:
                    # Eksikse yeniden oluştur
                    print("[UYARI] Anahtar dosyası eksik, yeniden oluşturuluyor...")
                    self._generate_and_save_keys()
            except Exception as e:
                print(f"[HATA] Anahtar dosyası okunamadı: {e}. Yeniden oluşturuluyor...")
                self._generate_and_save_keys()
        else:
            self._generate_and_save_keys()

        # Anahtarları Kullanıma Hazırla
        self.fernet = Fernet(self.key_fernet)
        self.aes = AESGCM(self.key_aes)
        self.chacha = ChaCha20Poly1305(self.key_chacha)
        
        # AESSIV anahtar boyutunu kontrol etmeden yüklemeye çalışırsa hata verebilir.
        # Bu yüzden try-except ile yakalayıp gerekirse yenilemek daha güvenlidir.
        try:
            self.siv = AESSIV(self.key_siv)
        except ValueError:
            print("[UYARI] AESSIV anahtarı uyumsuz, yeniden oluşturuluyor...")
            self._generate_and_save_keys()
            self.siv = AESSIV(self.key_siv)


    def _generate_and_save_keys(self):
        """Yeni anahtarlar üretir ve dosyaya yazar."""
        # 1. Fernet Key
        self.key_fernet = Fernet.generate_key()
        # 2. AES-GCM Key (256-bit / 32 byte)
        self.key_aes = AESGCM.generate_key(bit_length=256)
        # 3. ChaCha20 Key (256-bit / 32 byte)
        self.key_chacha = ChaCha20Poly1305.generate_key()
        
        # 4. AES-SIV Key (Düzeltme: 256-bit encryption için 512-bit/64 byte anahtar gerekir)
        # Veya kütüphanenin varsayılan generate_key fonksiyonunu bit_length parametresi OLMADAN kullanmak en güvenlisidir.
        self.key_siv = AESSIV.generate_key(bit_length=256) 

        with open(self.key_file, "wb") as f:
            f.write(self.key_fernet + b"\n")
            f.write(self.key_aes + b"\n")
            f.write(self.key_chacha + b"\n")
            f.write(self.key_siv + b"\n")
        
        print(f"[BİLGİ] Yeni anahtar dosyası oluşturuldu: {self.key_file}")

    def _b64_encode(self, data_bytes):
        return base64.b64encode(data_bytes).decode('utf-8')

    def _b64_decode(self, data_string):
        return base64.b64decode(data_string.encode('utf-8'))

    def encrypt_message(self, plaintext):
        algorithms = ['FERNET', 'AES-GCM', 'CHACHA20', 'AES-SIV']
        selected_algo = random.choice(algorithms)
        
        data_bytes = plaintext.encode('utf-8')
        result = {}

        if selected_algo == 'FERNET':
            token = self.fernet.encrypt(data_bytes)
            result = {
                'algo': 'FERNET',
                'ciphertext': self._b64_encode(token),
                'nonce': None
            }

        elif selected_algo == 'AES-GCM':
            nonce = os.urandom(12)
            ciphertext = self.aes.encrypt(nonce, data_bytes, None)
            result = {
                'algo': 'AES-GCM',
                'ciphertext': self._b64_encode(ciphertext),
                'nonce': self._b64_encode(nonce)
            }

        elif selected_algo == 'CHACHA20':
            nonce = os.urandom(12)
            ciphertext = self.chacha.encrypt(nonce, data_bytes, None)
            result = {
                'algo': 'CHACHA20',
                'ciphertext': self._b64_encode(ciphertext),
                'nonce': self._b64_encode(nonce)
            }

        elif selected_algo == 'AES-SIV':
            # AES-SIV nonce gerektirmez (deterministic encryption)
            # Ancak güvenli olması için 'associated_data' listesi boş geçilebilir
            ciphertext = self.siv.encrypt(data_bytes, []) 
            result = {
                'algo': 'AES-SIV',
                'ciphertext': self._b64_encode(ciphertext),
                'nonce': None
            }

        return result

    def decrypt_message(self, encrypted_package):
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
            
            elif algo == 'AES-SIV':
                decrypted_bytes = self.siv.decrypt(ciphertext, [])
            
            else:
                return "HATA: Bilinmeyen algoritma!"

            return decrypted_bytes.decode('utf-8')
        
        except Exception as e:
            # Hata detayını terminale yazdıralım ki görelim
            print(f"[DECRYPT ERROR] {str(e)}")
            return "ŞİFRE ÇÖZME HATASI: Anahtar değişmiş veya veri bozulmuş."