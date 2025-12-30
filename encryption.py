import os
import base64
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, 
    ChaCha20Poly1305, 
    AESSIV
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class MultiAlgoCrypto:
    def __init__(self):
        

        self.passphrase = os.getenv("MASTER_KEY_PASSPHRASE")
        if not self.passphrase:
            raise ValueError("HATA: .env dosyasında 'MASTER_KEY_PASSPHRASE' bulunamadı!")
        
        self._derive_keys_from_passphrase()

        print("--- GÜVENLİK SİSTEMİ BAŞLATILDI ---")
        print(f"[INFO] 4 Algoritma Yüklendi. Anahtarlar ortak paroladan türetildi.")
        print("-------------------------------------")

    def _derive_keys_from_passphrase(self):
   
    # Güvenlik Notu: Gerçek hayatta Salt rastgele olmalı ve saklanmalıdır.
        fixed_salt = b'Grup34_Sabit_Tuz_Degeri_2025' 

    # 1. Ana Anahtarı Türet (128 byte lazım: 4 tane 32-byte anahtar için)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=128, 
            salt=fixed_salt,
            iterations=100000,
        )
        master_key_bytes = kdf.derive(self.passphrase.encode())

        # Anahtarları Parçala (Slicing)
        # Fernet için 32 byte anahtarın base64 hali gerekir
        self.key_fernet = base64.urlsafe_b64encode(master_key_bytes[0:32])
        self.key_aes = master_key_bytes[32:64]
        self.key_chacha = master_key_bytes[64:96]
        self.key_siv = master_key_bytes[96:128]

        # Anahtarları Yükle
        self.fernet = Fernet(self.key_fernet)
        self.aes = AESGCM(self.key_aes)
        self.chacha = ChaCha20Poly1305(self.key_chacha)
        try:
            self.siv = AESSIV(self.key_siv)
        except:
            # SIV bazen 64 byte ister, o zaman KDF length arttırılmalı
            pass




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