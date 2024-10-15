import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class DoubleRatchet:
    def __init__(self, key):
        self.key = key  # Kunci simetris awal

    def ratchet(self):
        """Perbarui kunci untuk setiap pesan."""
        self.key = os.urandom(32)

    def encrypt(self, plaintext):
        """Enkripsi dengan AES CBC."""
        iv = os.urandom(16)  # IV harus selalu 16 bytes untuk CBC
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding agar sesuai dengan block size AES (16 bytes)
        padding_length = 16 - len(plaintext) % 16
        padded_plaintext = plaintext + bytes([padding_length]) * padding_length

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext  # Gabungkan IV dengan ciphertext

    def decrypt(self, ciphertext):
        """Dekripsi dengan AES CBC."""
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too short to contain IV")

        # Pisahkan IV dan ciphertext
        iv = ciphertext[:16]  # IV harus tepat 16 bytes
        actual_ciphertext = ciphertext[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()

        # Hapus padding
        padding_length = decrypted_padded[-1]
        return decrypted_padded[:-padding_length]
