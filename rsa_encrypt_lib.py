import zlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


class PngEncryptor:
    """
    Klasa do szyfrowania i deszyfrowania danych PNG przy użyciu algorytmu RSA i AES w różnych trybach.

    Wykorzystuje podejście hybrydowe:
    - RSA do szyfrowania klucza sesji AES.
    - AES do szyfrowania danych w trybie blokowym.

    Tryby szyfrowania AES:
    - ECB: Każdy blok danych jest szyfrowany niezależnie, co może być mniej bezpieczne, gdy dane mają powtarzające się wzorce.
    - CBC: Każdy blok plaintext jest XORowany z poprzednim blokiem ciphertext przed szyfrowaniem. Pierwszy blok jest XORowany z wektorem inicjalizującym (IV).
    - CFB: Tryb sprzężenia zwrotnego szyfrowania. Podobny do CBC, ale operacje są wykonywane na mniejszych blokach.
    - OFB: Blok IV jest szyfrowany, a wynik jest XORowany z blokiem plaintext. Szyfrowanie jest wykonywane na poprzednim szyfrowanym bloku zamiast plaintextu.
    - CTR: Tryb licznika. Nonce jest używany razem z licznikiem do generowania strumienia klucza, który jest następnie XORowany z plaintextem.
    """

    def __init__(self, rsa_key=None):
        """
        Inicjalizuje obiekt PngEncryptor z kluczem RSA.

        :param rsa_key: Krotka zawierająca klucz prywatny i publiczny RSA. Jeśli nie jest podana, generowane są nowe klucze.
        """
        if rsa_key:
            self.rsa_private_key, self.rsa_public_key = rsa_key
        else:
            self.rsa_private_key = None
            self.rsa_public_key = None

    def generate_keys(self, key_size=2048):
        """
        Generuje klucze RSA o określonym rozmiarze.

        :param key_size: Rozmiar klucza w bitach (domyślnie 2048).
        """
        key = RSA.generate(key_size)
        self.rsa_private_key = key
        self.rsa_public_key = key.publickey()

    @staticmethod
    def read_png_chunks(file):
        """
        Odczytuje plik PNG i dzieli go na chunki.

        :param file: Ścieżka do pliku PNG.
        :return: Podpis pliku i lista chunków.
        """
        chunks = []
        with open(file, "rb") as f:
            signature = f.read(8)
            while True:
                length = int.from_bytes(f.read(4), "big")
                chunk_type = f.read(4)
                chunk_data = f.read(length)
                crc = f.read(4)
                chunks.append((chunk_type, chunk_data))
                if chunk_type == b"IEND":
                    break
        return signature, chunks

    @staticmethod
    def write_png_chunks(file, signature, chunks):
        """
        Zapisuje chunki do pliku PNG.

        :param file: Ścieżka do pliku PNG.
        :param signature: Podpis pliku PNG.
        :param chunks: Lista chunków do zapisania.
        """
        with open(file, "wb") as f:
            f.write(signature)
            for chunk_type, chunk_data in chunks:
                f.write(len(chunk_data).to_bytes(4, "big"))
                f.write(chunk_type)
                f.write(chunk_data)
                crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                f.write(crc.to_bytes(4, "big"))

    def encrypt_data(self, data, mode="ECB"):
        """
        Szyfruje dane przy użyciu AES w określonym trybie i klucza sesji szyfrowanego RSA.

        :param data: Dane do zaszyfrowania.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        :return: Zaszyfrowane dane zawierające zaszyfrowany klucz sesji, IV i szyfrogram.
        """
        session_key = get_random_bytes(16)  # Klucz AES o długości 16 bajtów (128 bitów)
        cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        if mode == "ECB":
            cipher_aes = AES.new(session_key, AES.MODE_ECB)
            padded_data = pad(data, AES.block_size)
            ciphertext = cipher_aes.encrypt(padded_data)
            return enc_session_key + ciphertext

        iv = get_random_bytes(16)  # Wektor inicjalizujący dla innych trybów
        if mode == "CBC":
            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher_aes = AES.new(session_key, AES.MODE_OFB, iv)
        elif mode == "CTR":
            cipher_aes = AES.new(session_key, AES.MODE_CTR, nonce=iv[:8])
        else:
            raise ValueError(
                "Unsupported mode: choose from 'ECB', 'CBC', 'CFB', 'OFB', 'CTR'"
            )

        ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
        return enc_session_key + iv + ciphertext

    def decrypt_data(self, encrypted_data, mode="ECB"):
        """
        Odszyfrowuje dane przy użyciu AES w określonym trybie i klucza sesji odszyfrowanego RSA.

        :param encrypted_data: Zaszyfrowane dane.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        :return: Odszyfrowane dane.
        """
        enc_session_key_size = self.rsa_private_key.size_in_bytes()
        enc_session_key = encrypted_data[:enc_session_key_size]
        session_key = PKCS1_OAEP.new(self.rsa_private_key).decrypt(enc_session_key)

        if mode == "ECB":
            ciphertext = encrypted_data[enc_session_key_size:]
            cipher_aes = AES.new(session_key, AES.MODE_ECB)
            padded_data = cipher_aes.decrypt(ciphertext)
            return unpad(padded_data, AES.block_size)

        iv_size = 16
        iv = encrypted_data[enc_session_key_size : enc_session_key_size + iv_size]
        ciphertext = encrypted_data[enc_session_key_size + iv_size :]

        if mode == "CBC":
            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        elif mode == "CFB":
            cipher_aes = AES.new(session_key, AES.MODE_CFB, iv)
        elif mode == "OFB":
            cipher_aes = AES.new(session_key, AES.MODE_OFB, iv)
        elif mode == "CTR":
            cipher_aes = AES.new(session_key, AES.MODE_CTR, nonce=iv[:8])
        else:
            raise ValueError(
                "Unsupported mode: choose from 'ECB', 'CBC', 'CFB', 'OFB', 'CTR'"
            )

        padded_data = cipher_aes.decrypt(ciphertext)
        return unpad(padded_data, AES.block_size)

    def encrypt_png_decompress_first(self, input_file, output_file, mode="ECB"):
        """
        Szyfruje zdekompresowane dane IDAT w pliku PNG, a następnie kompresuje tak utworzony szyfrogram.

        :param input_file: Ścieżka do pliku wejściowego PNG.
        :param output_file: Ścieżka do pliku wyjściowego PNG.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        """
        signature, chunks = self.read_png_chunks(input_file)
        encrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decompressed_data = zlib.decompress(chunk_data)
                encrypted_data = self.encrypt_data(decompressed_data, mode)
                compressed_encrypted_data = zlib.compress(encrypted_data)
                encrypted_chunks.append((chunk_type, compressed_encrypted_data))
            else:
                encrypted_chunks.append((chunk_type, chunk_data))
        self.write_png_chunks(output_file, signature, encrypted_chunks)

    def decrypt_png_decompress_first(self, input_file, output_file, mode="ECB"):
        """
        Deszyfruje zdekompresowane dane IDAT w pliku PNG, a następnie kompresuje tak odszyfrowane dane.

        :param input_file: Ścieżka do pliku wejściowego PNG.
        :param output_file: Ścieżka do pliku wyjściowego PNG.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        """
        if not self.rsa_private_key:
            raise ValueError("RSA private key is required for decryption.")
        signature, chunks = self.read_png_chunks(input_file)
        decrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decompressed_data = zlib.decompress(chunk_data)
                decrypted_data = self.decrypt_data(decompressed_data, mode)
                compressed_decrypted_data = zlib.compress(decrypted_data)
                decrypted_chunks.append((chunk_type, compressed_decrypted_data))
            else:
                decrypted_chunks.append((chunk_type, chunk_data))
        self.write_png_chunks(output_file, signature, decrypted_chunks)

    def encrypt_png_compress_first(self, input_file, output_file, mode="ECB"):
        """
        Szyfruje skompresowane dane IDAT w pliku PNG.

        :param input_file: Ścieżka do pliku wejściowego PNG.
        :param output_file: Ścieżka do pliku wyjściowego PNG.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        """
        signature, chunks = self.read_png_chunks(input_file)
        encrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                compressed_data = zlib.compress(chunk_data)
                padded_data = pad(compressed_data, AES.block_size)
                encrypted_data = self.encrypt_data(padded_data, mode)
                encrypted_chunks.append((chunk_type, encrypted_data))
            else:
                encrypted_chunks.append((chunk_type, chunk_data))
        self.write_png_chunks(output_file, signature, encrypted_chunks)

    def decrypt_png_compress_first(self, input_file, output_file, mode="ECB"):
        """
        Deszyfruje skompresowane dane IDAT w pliku PNG.

        :param input_file: Ścieżka do pliku wejściowego PNG.
        :param output_file: Ścieżka do pliku wyjściowego PNG.
        :param mode: Tryb szyfrowania AES (domyślnie "ECB").
        """
        if not self.rsa_private_key:
            raise ValueError("RSA private key is required for decryption.")
        signature, chunks = self.read_png_chunks(input_file)
        decrypted_chunks = []
        for chunk_type, chunk_data in chunks:
            if chunk_type == b"IDAT":
                decrypted_data = self.decrypt_data(chunk_data, mode)
                unpadded_data = unpad(decrypted_data, AES.block_size)
                decompressed_decrypted_data = zlib.decompress(unpadded_data)
                decrypted_chunks.append((chunk_type, decompressed_decrypted_data))
            else:
                decrypted_chunks.append((chunk_type, chunk_data))
        self.write_png_chunks(output_file, signature, decrypted_chunks)


# Przykład użycia
encryptor = PngEncryptor()
encryptor.generate_keys()

# Ścieżki do plików
input_file = "square.png"
output_file_encrypted = "encrypted.png"
output_file_decrypted = "decrypted.png"

# Szyfrowanie pliku PNG (dekompresja przed szyfrowaniem)
encryptor.encrypt_png_decompress_first(input_file, output_file_encrypted, mode="CBC")

# Deszyfrowanie pliku PNG (dekompresja przed deszyfrowaniem)
encryptor.decrypt_png_decompress_first(
    output_file_encrypted, output_file_decrypted, mode="CBC"
)
