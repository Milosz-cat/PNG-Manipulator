import os
import struct
import zlib
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from tqdm import tqdm


class RSA:
    """
    Implementacja algorytmu RSA z różnymi trybami szyfrowania.

    Tryby szyfrowania:
    - ECB: Najprostszy tryb, gdzie każdy blok jest szyfrowany niezależnie. Jest najmniej bezpieczny, ponieważ identyczne bloki w plaintext dają identyczne bloki w ciphertext.
    - OFB: Blok IV jest szyfrowany, a wynik jest XORowany z blokiem plaintext, aby utworzyć blok ciphertext. W następnym kroku szyfrowanie jest wykonywane na poprzednim szyfrowanym bloku zamiast plaintextu.
    - CTR: Tryb licznika. Nonce jest używany razem z licznikiem do generowania strumienia klucza, który jest następnie XORowany z plaintextem.
    - CFB: Tryb sprzężenia zwrotnego szyfrowania. Podobnie jak w trybie CBC, ale operacje są wykonywane na mniejszych blokach.
    """

    def __init__(self, key_size=2048):
        """
        Inicjalizuje algorytm RSA z określonym rozmiarem klucza.

        :param key_size: Rozmiar klucza w bitach.
        """
        self.key_size = key_size
        self.e = 65537
        self.generate_keys()

    def generate_keys(self):
        """
        Generuje klucze publiczne i prywatne RSA.
        """
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.d = number.inverse(self.e, self.phi)
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    def pad(self, data):
        """
        Dodaje padding do danych, aby zapewnić, że są wielokrotnością rozmiaru bloku.

        :param data: Dane do wyściełania.
        :return: Dane z dodanym paddingiem.
        """
        padding_length = self.key_size // 8 - 1 - len(data) % (self.key_size // 8 - 1)
        return data + bytes([padding_length] * padding_length)

    def unpad(self, data):
        """
        Usuwa padding z danych.

        :param data: Dane z paddingiem.
        :return: Dane bez paddingu.
        """
        padding_length = data[-1]
        return data[:-padding_length]

    def encrypt_ofb(self, plaintext, iv):
        """
        Szyfruje dane w trybie OFB.
        """
        e, n = self.public_key
        ciphertext = []
        feedback = iv
        for i in tqdm(
            range(0, len(plaintext), self.key_size // 8 - 1),
            desc="OFB | (En/De)crypting:",
        ):
            output_block = pow(int.from_bytes(feedback, byteorder="big"), e, n)
            output_bytes = output_block.to_bytes(self.key_size // 8, byteorder="big")
            block = plaintext[i : i + self.key_size // 8 - 1]
            encrypted_block = bytes(
                [x ^ y for x, y in zip(block, output_bytes[: len(block)])]
            )
            ciphertext.extend(encrypted_block)
            feedback = output_bytes
        return bytes(ciphertext)

    def decrypt_ofb(self, ciphertext, iv):
        """
        Odszyfrowuje dane w trybie OFB.
        """
        return self.encrypt_ofb(ciphertext, iv)

    def encrypt_ecb(self, plaintext):
        """
        Szyfruje dane w trybie ECB.
        """
        e, n = self.public_key
        ciphertext = []
        for i in tqdm(
            range(0, len(plaintext), self.key_size // 8 - 1), desc="ECB | Encrypting:"
        ):
            block = plaintext[i : i + self.key_size // 8 - 1]
            encrypted_block = pow(int.from_bytes(block, byteorder="big"), e, n)
            encrypted_block_bytes = encrypted_block.to_bytes(
                self.key_size // 8, byteorder="big"
            )
            ciphertext.extend(encrypted_block_bytes)
        return bytes(ciphertext)

    def decrypt_ecb(self, ciphertext):
        """
        Odszyfrowuje dane w trybie ECB.
        """
        d, n = self.private_key
        plaintext = []
        for i in tqdm(
            range(0, len(ciphertext), self.key_size // 8), desc="ECB | Decrypting:"
        ):
            block = ciphertext[i : i + self.key_size // 8]
            decrypted_block = pow(int.from_bytes(block, byteorder="big"), d, n)
            decrypted_block_bytes = decrypted_block.to_bytes(
                self.key_size // 8 - 1, byteorder="big"
            )
            plaintext.extend(decrypted_block_bytes)
        return bytes(plaintext)

    def encrypt_ctr(self, plaintext, nonce):
        """
        Szyfruje dane w trybie CTR.

        :param plaintext: Dane do zaszyfrowania.
        :param nonce: Wartość nonce do użycia w trybie CTR.
        :return: Zaszyfrowane dane.
        """
        e, n = self.public_key
        ciphertext = []
        counter = 0
        for i in tqdm(
            range(0, len(plaintext), self.key_size // 8 - 1),
            desc="CTR | (En/De)crypting:",
        ):
            counter_block = (
                nonce
                + counter.to_bytes(16, byteorder="big")[-(self.key_size // 8 - 1) :]
            )
            key_stream = pow(int.from_bytes(counter_block, byteorder="big"), e, n)
            key_stream_bytes = key_stream.to_bytes(self.key_size // 8, byteorder="big")
            block = plaintext[i : i + self.key_size // 8 - 1]
            encrypted_block = bytes(
                [x ^ y for x, y in zip(block, key_stream_bytes[: len(block)])]
            )
            ciphertext.extend(encrypted_block)
            counter += 1
        return bytes(ciphertext)

    def decrypt_ctr(self, ciphertext, nonce):
        """
        Odszyfrowuje dane w trybie CTR.
        """
        return self.encrypt_ctr(ciphertext, nonce)

    def encrypt_cfb(self, plaintext, iv):
        """
        Szyfruje dane w trybie CFB.

        """
        e, n = self.public_key
        ciphertext = []
        previous_block = iv
        for i in tqdm(
            range(0, len(plaintext), self.key_size // 8 - 1), desc="CFB | Encrypting:"
        ):
            output_block = pow(int.from_bytes(previous_block, byteorder="big"), e, n)
            output_bytes = output_block.to_bytes(self.key_size // 8, byteorder="big")
            block = plaintext[i : i + self.key_size // 8 - 1]
            encrypted_block = bytes(
                [x ^ y for x, y in zip(block, output_bytes[: len(block)])]
            )
            ciphertext.extend(encrypted_block)
            previous_block = encrypted_block
        return bytes(ciphertext)

    def decrypt_cfb(self, ciphertext, iv):
        """
        Odszyfrowuje dane w trybie CFB.
        """
        e, n = self.public_key
        plaintext = []
        previous_block = iv
        for i in tqdm(
            range(0, len(ciphertext), self.key_size // 8 - 1), desc="CFB | Decrypting:"
        ):
            output_block = pow(int.from_bytes(previous_block, byteorder="big"), e, n)
            output_bytes = output_block.to_bytes(self.key_size // 8, byteorder="big")
            block = ciphertext[i : i + self.key_size // 8 - 1]
            decrypted_block = bytes(
                [x ^ y for x, y in zip(block, output_bytes[: len(block)])]
            )
            plaintext.extend(decrypted_block)
            previous_block = block
        return bytes(plaintext)


class PNGEncryptor:
    """
    Klasa do szyfrowania i deszyfrowania danych PNG przy użyciu algorytmu RSA w różnych trybach.
    """

    def __init__(self, rsa, mode="CBC"):
        """
        Inicjalizuje obiekt PNGEncryptor z określonym trybem szyfrowania.

        :param rsa: Obiekt klasy RSA do szyfrowania i deszyfrowania.
        :param mode: Tryb szyfrowania (domyślnie "CBC").
        """
        self.rsa = rsa
        self.mode = mode

    def encrypt_idat(self, iv, nonce=None):
        """
        Szyfruje skompresowane dane IDAT w pliku PNG.

        :param iv: Wektor inicjalizujący.
        :param nonce: Wartość nonce (tylko dla trybu CTR).
        """
        for i, (chunk_type, chunk_data, crc) in enumerate(self.chunks):
            if chunk_type == b"IDAT":
                if self.mode == "CTR" and nonce is not None:
                    encrypted_data = self.rsa.encrypt_ctr(chunk_data, nonce)
                elif self.mode in ["OFB", "CFB"]:
                    encrypted_data = getattr(self.rsa, f"encrypt_{self.mode.lower()}")(
                        chunk_data, iv
                    )
                elif self.mode == "ECB":
                    encrypted_data = self.rsa.encrypt_ecb(chunk_data)
                else:
                    raise ValueError(f"Unsupported mode {self.mode}")
                self.chunks[i] = (chunk_type, encrypted_data, crc)
                break

    def decrypt_idat(self, iv, nonce=None):
        """
        Deszyfruje skompresowane dane IDAT w pliku PNG.

        :param iv: Wektor inicjalizujący.
        :param nonce: Wartość nonce (tylko dla trybu CTR).
        """
        for i, (chunk_type, chunk_data, crc) in enumerate(self.chunks):
            if chunk_type == b"IDAT":
                if self.mode == "CTR" and nonce is not None:
                    decrypted_data = self.rsa.decrypt_ctr(chunk_data, nonce)
                elif self.mode in ["OFB", "CFB"]:
                    decrypted_data = getattr(self.rsa, f"decrypt_{self.mode.lower()}")(
                        chunk_data, iv
                    )
                elif self.mode == "ECB":
                    decrypted_data = self.rsa.decrypt_ecb(chunk_data)
                else:
                    raise ValueError(f"Unsupported mode {self.mode}")
                self.chunks[i] = (chunk_type, decrypted_data, crc)
                break

    def read_png(self, file_path):
        """
        Odczytuje plik PNG i dzieli go na chunki.

        :param file_path: Ścieżka do pliku PNG.
        """
        with open(file_path, "rb") as f:
            self.png_data = f.read()
        self.signature = self.png_data[:8]
        self.chunks = self._split_chunks(self.png_data[8:])

    def _split_chunks(self, data):
        """
        Dzieli dane PNG na chunki.

        :param data: Dane PNG.
        :return: Lista chunków (typ, dane, crc).
        """
        chunks = []
        i = 0
        while i < len(data):
            length = struct.unpack("!I", data[i : i + 4])[0]
            chunk_type = data[i + 4 : i + 8]
            chunk_data = data[i + 8 : i + 8 + length]
            crc = data[i + 8 + length : i + 12 + length]
            chunks.append((chunk_type, chunk_data, crc))
            i += 12 + length
        return chunks

    def save_png(self, output_path):
        """
        Zapisuje plik PNG z zaszyfrowanymi danymi.

        :param output_path: Ścieżka do zapisu pliku PNG.
        """
        with open(output_path, "wb") as f:
            f.write(self.signature)
            for chunk_type, chunk_data, crc in self.chunks:
                f.write(struct.pack("!I", len(chunk_data)))
                f.write(chunk_type)
                f.write(chunk_data)
                f.write(crc)


# Przykład użycia
rsa = RSA(key_size=2048)  # 1024 512

modes = ["ECB", "OFB", "CTR", "CFB"]  # "ECB", "OFB", "CTR", "CFB"

# Upewnij się, że katalogi istnieją
os.makedirs("encrypted/compress", exist_ok=True)
os.makedirs("decrypted/compress", exist_ok=True)

for m in modes:
    encryptor = PNGEncryptor(rsa, mode=m)  # Wybierz tryb
    encryptor.read_png("square.png")
    iv = get_random_bytes(16)  # Wektor inicjalizujący
    nonce = (
        get_random_bytes(16) if m == "CTR" else None
    )  # Generuj nonce tylko dla trybu CTR

    encrypted_path = f"encrypted/compress/encrypted_{m}_compress.png"
    decrypted_path = f"decrypted/compress/decrypted_{m}_compress.png"

    if m == "CTR":
        encryptor.encrypt_idat(
            iv, nonce
        )  # Przekaż zarówno IV, jak i nonce dla trybu CTR
    else:
        encryptor.encrypt_idat(iv)  # Przekaż tylko IV dla innych trybów

    encryptor.save_png(encrypted_path)

    decryptor = PNGEncryptor(rsa, mode=m)
    decryptor.read_png(encrypted_path)
    if m == "CTR":
        decryptor.decrypt_idat(
            iv, nonce
        )  # Przekaż zarówno IV, jak i nonce dla trybu CTR
    else:
        decryptor.decrypt_idat(iv)  # Przekaż tylko IV dla innych trybów

    decryptor.save_png(decrypted_path)
