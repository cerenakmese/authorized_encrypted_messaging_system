import os
import base64
import random

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, 
    ChaCha20Poly1305, 
    AESSIV, 
    XChaCha20Poly1305
)


class MultiAlgoCrypto:
    def __init__(self):

        # 1. Fernet (AES-128 + HMAC)
        self.key_fernet = Fernet.generate_key()
        self.fernet = Fernet(self.key_fernet)

        # 2. AES-GCM (256-bit)
        self.key_aes = AESGCM.generate_key(bit_length=256)
        self.aes = AESGCM(self.key_aes)

        # 3. ChaCha20-Poly1305
        self.key_chacha = ChaCha20Poly1305.generate_key()
        self.chacha = ChaCha20Poly1305(self.key_chacha)

        # 4. XChaCha20-Poly1305 (Yeni)
        self.key_xchacha = XChaCha20Poly1305.generate_key()
        self.xchacha = XChaCha20Poly1305(self.key_xchacha)

        # 5. AES-SIV (Yeni) - nonce gerektirmez
        self.key_siv = AESSIV.generate_key(bit_length=256)
        self.siv = AESSIV(self.key_siv)

        print(">>> Şifreleme sistemi başlatıldı (5 algoritma yüklendi).")


    def _b64_encode(self, b):
        return base64.b64encode(b).decode()

    def _b64_decode(self, s):
        return base64.b64decode(s)


    def encrypt_message(self, plaintext):
        algorithms = ["FERNET", "AES-GCM", "CHACHA20", "XCHACHA20", "AES-SIV"]
        selected_algo = random.choice(algorithms)

        data_bytes = plaintext.encode()
        result = {}

        # ---------- FERNET ----------
        if selected_algo == "FERNET":
            token = self.fernet.encrypt(data_bytes)
            result = {
                "algo": "FERNET",
                "ciphertext": self._b64_encode(token),
                "nonce": None
            }

        # ---------- AES-GCM ----------
        elif selected_algo == "AES-GCM":
            nonce = os.urandom(12)
            ciphertext = self.aes.encrypt(nonce, data_bytes, None)
            result = {
                "algo": "AES-GCM",
                "ciphertext": self._b64_encode(ciphertext),
                "nonce": self._b64_encode(nonce)
            }

        # ---------- CHACHA20 ----------
        elif selected_algo == "CHACHA20":
            nonce = os.urandom(12)
            ciphertext = self.chacha.encrypt(nonce, data_bytes, None)
            result = {
                "algo": "CHACHA20",
                "ciphertext": self._b64_encode(ciphertext),
                "nonce": self._b64_encode(nonce)
            }

        # ---------- XCHACHA20 (Yeni) ----------
        elif selected_algo == "XCHACHA20":
            nonce = os.urandom(24)  # uzun nonce avantajı
            ciphertext = self.xchacha.encrypt(nonce, data_bytes, None)
            result = {
                "algo": "XCHACHA20",
                "ciphertext": self._b64_encode(ciphertext),
                "nonce": self._b64_encode(nonce)
            }

        # ---------- AES-SIV (Yeni) ----------
        elif selected_algo == "AES-SIV":
            ciphertext = self.siv.encrypt(data_bytes, [])  # nonce gerekmez
            result = {
                "algo": "AES-SIV",
                "ciphertext": self._b64_encode(ciphertext),
                "nonce": None
            }

        print(f"[LOG] Mesaj {selected_algo} ile şifrelendi.")
        return result


    def decrypt_message(self, package):
        algo = package["algo"]
        ciphertext = self._b64_decode(package["ciphertext"])

        try:
            if algo == "FERNET":
                return self.fernet.decrypt(ciphertext).decode()

            elif algo == "AES-GCM":
                nonce = self._b64_decode(package["nonce"])
                return self.aes.decrypt(nonce, ciphertext, None).decode()

            elif algo == "CHACHA20":
                nonce = self._b64_decode(package["nonce"])
                return self.chacha.decrypt(nonce, ciphertext, None).decode()

            elif algo == "XCHACHA20":
                nonce = self._b64_decode(package["nonce"])
                return self.xchacha.decrypt(nonce, ciphertext, None).decode()

            elif algo == "AES-SIV":
                return self.siv.decrypt(ciphertext, []).decode()

            else:
                return "HATA: Bilinmeyen algoritma!"

        except Exception as e:
            return f"Çözme Hatası: {e}"
