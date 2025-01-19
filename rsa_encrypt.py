import os
import struct
import zlib
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from tqdm import tqdm
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes


class RSA:
    """
    Implementacja algorytmu RSA z różnymi trybami szyfrowania.

    Tryby szyfrowania:
    - ECB z paddingiem OAEP.: Najprostszy tryb, gdzie każdy blok jest szyfrowany niezależnie. Jest najmniej bezpieczny, ponieważ identyczne bloki w plaintext dają identyczne bloki w ciphertext.
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

    def mgf1(self, seed, mask_len, hash_function=hashlib.sha256):
        """
        Mask Generation Function 1 (MGF1) używana w paddingu OAEP.

        :param seed: Ziarno do wygenerowania maski.
        :param mask_len: Długość maski.
        :param hash_function: Funkcja haszująca używana do generowania maski (domyślnie SHA-256).
        :return: Wygenerowana maska.
        """
        mask = b""
        for counter in range(0, -(-mask_len // hash_function().digest_size)):
            C = long_to_bytes(counter, 4)
            mask += hash_function(seed + C).digest()
        return mask[:mask_len]

    def oaep_pad(self, message, k, hash_function=hashlib.sha256):
        """
        Optimal Asymmetric Encryption Padding (OAEP) dla RSA.

        :param message: Wiadomość do spadowania.
        :param k: Rozmiar bloku w bajtach.
        :param hash_function: Funkcja haszująca używana w paddingu (domyślnie SHA-256).
        :return: Spadowana wiadomość.
        """
        m_len = len(message)
        h_len = hash_function().digest_size

        ps = b"\x00" * (k - m_len - 2 * h_len - 2)
        db = hash_function(b"").digest() + ps + b"\x01" + message

        seed = get_random_bytes(h_len)
        db_mask = self.mgf1(seed, k - h_len - 1, hash_function)
        masked_db = bytes([x ^ y for x, y in zip(db, db_mask)])

        seed_mask = self.mgf1(masked_db, h_len, hash_function)
        masked_seed = bytes([x ^ y for x, y in zip(seed, seed_mask)])

        return b"\x00" + masked_seed + masked_db

    def oaep_unpad(self, padded_message, k, hash_function=hashlib.sha256):
        """
        Dekodowanie paddingu OAEP dla RSA.

        :param padded_message: Spadowana wiadomość do odspadowania.
        :param k: Rozmiar bloku w bajtach.
        :param hash_function: Funkcja haszująca używana w paddingu (domyślnie SHA-256).
        :return: Odszyfrowana wiadomość.
        """
        h_len = hash_function().digest_size

        if len(padded_message) != k or padded_message[0] != 0:
            raise ValueError("Błąd deszyfrowania")

        y, masked_seed, masked_db = (
            padded_message[0],
            padded_message[1 : h_len + 1],
            padded_message[h_len + 1 :],
        )
        seed_mask = self.mgf1(masked_db, h_len, hash_function)
        seed = bytes([x ^ y for x, y in zip(masked_seed, seed_mask)])

        db_mask = self.mgf1(seed, k - h_len - 1, hash_function)
        db = bytes([x ^ y for x, y in zip(masked_db, db_mask)])

        l_hash, ps_m = db[:h_len], db[h_len:]
        if l_hash != hash_function(b"").digest():
            raise ValueError("Błąd deszyfrowania")

        try:
            separator_index = ps_m.index(b"\x01")
        except ValueError:
            raise ValueError("Błąd deszyfrowania")

        return ps_m[separator_index + 1 :]

    def encrypt_ecb(self, plaintext):
        """
        Szyfruje dane w trybie ECB z użyciem paddingu OAEP.

        :param plaintext: Dane do zaszyfrowania.
        :return: Zaszyfrowane dane.
        """
        e, n = self.public_key
        k = (self.key_size + 7) // 8
        ciphertext = []
        for i in tqdm(
            range(0, len(plaintext), k - 2 * hashlib.sha256().digest_size - 2),
            desc="ECB | Encrypting:",
        ):
            block = plaintext[i : i + k - 2 * hashlib.sha256().digest_size - 2]
            padded_block = self.oaep_pad(block, k)
            block_int = bytes_to_long(padded_block)
            encrypted_block_int = pow(block_int, e, n)
            encrypted_block = long_to_bytes(encrypted_block_int, k)
            ciphertext.extend(encrypted_block)
        return bytes(ciphertext)

    def decrypt_ecb(self, ciphertext):
        """
        Odszyfrowuje dane w trybie ECB z użyciem paddingu OAEP.

        :param ciphertext: Zaszyfrowane dane.
        :return: Odszyfrowane dane.
        """
        d, n = self.private_key
        k = (self.key_size + 7) // 8
        plaintext = []
        for i in tqdm(range(0, len(ciphertext), k), desc="ECB | Decrypting:"):
            block = ciphertext[i : i + k]
            block_int = bytes_to_long(block)
            decrypted_block_int = pow(block_int, d, n)
            decrypted_block = long_to_bytes(decrypted_block_int, k)
            unpadded_block = self.oaep_unpad(decrypted_block, k)
            plaintext.extend(unpadded_block)
        return bytes(plaintext)

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

        :param ciphertext: Zaszyfrowane dane.
        :param nonce: Wartość nonce do użycia w trybie CTR.
        :return: Odszyfrowane dane.
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

    def __init__(self, rsa, mode="EBC"):
        """
        Inicjalizuje obiekt PNGEncryptor z określonym trybem szyfrowania.

        :param rsa: Obiekt klasy RSA do szyfrowania i deszyfrowania.
        :param mode: Tryb szyfrowania (domyślnie "ECB").
        """
        self.rsa = rsa
        self.mode = mode

    def read_png(self, file_path):
        """
        Odczytuje plik PNG i wydobywa chunki IDAT.

        :param file_path: Ścieżka do pliku PNG.
        """
        self.chunks = []
        with open(file_path, "rb") as f:
            # Weryfikacja sygnatury PNG
            PngSignature = b"\x89PNG\r\n\x1a\n"
            if f.read(len(PngSignature)) != PngSignature:
                raise Exception("Invalid PNG Signature")

            # Wczytanie wszystkich chunków
            while True:
                chunk_type, chunk_data = self._read_chunk(f)
                self.chunks.append((chunk_type, chunk_data))
                if chunk_type == b"IEND":
                    break

        self.IDAT_data = b"".join(
            chunk_data
            for chunk_type, chunk_data in self.chunks
            if chunk_type == b"IDAT"
        )

    def _read_chunk(self, f):
        chunk_length, chunk_type = struct.unpack(">I4s", f.read(8))
        chunk_data = f.read(chunk_length)
        (chunk_expected_crc,) = struct.unpack(">I", f.read(4))
        chunk_actual_crc = zlib.crc32(
            chunk_data, zlib.crc32(struct.pack(">4s", chunk_type))
        )
        if chunk_expected_crc != chunk_actual_crc:
            raise Exception("chunk checksum failed")
        return chunk_type, chunk_data

    def _decompress_idat(self):
        return zlib.decompress(self.IDAT_data)

    def _compress_idat(self, data):
        return zlib.compress(data)

    def encrypt_idat(self, iv, nonce=None):
        """
        Szyfruje zdekompresowane dane IDAT w pliku PNG, a następnie kompresuje tak utworzony szyfrogram.

        :param iv: Wektor inicjalizujący.
        :param nonce: Wartość nonce (tylko dla trybu CTR).
        """
        decompressed_data = self._decompress_idat()
        if self.mode == "CTR" and nonce is not None:
            encrypted_data = self.rsa.encrypt_ctr(decompressed_data, nonce)
        elif self.mode in ["OFB", "CFB"]:
            encrypted_data = getattr(self.rsa, f"encrypt_{self.mode.lower()}")(
                decompressed_data, iv
            )
        elif self.mode == "ECB":
            encrypted_data = self.rsa.encrypt_ecb(decompressed_data)
        else:
            raise ValueError(f"Unsupported mode {self.mode}")
        self.encrypted_compressed_data = self._compress_idat(encrypted_data)

    def decrypt_idat(self, iv, nonce=None):
        """
        Deszyfruje zdekompresowane dane IDAT w pliku PNG, a następnie kompresuje tak odszyfrowane dane.

        :param iv: Wektor inicjalizujący.
        :param nonce: Wartość nonce (tylko dla trybu CTR).
        """
        decompressed_data = self._decompress_idat()
        if self.mode == "CTR" and nonce is not None:
            decrypted_data = self.rsa.decrypt_ctr(decompressed_data, nonce)
        elif self.mode in ["OFB", "CFB"]:
            decrypted_data = getattr(self.rsa, f"decrypt_{self.mode.lower()}")(
                decompressed_data, iv
            )
        elif self.mode == "ECB":
            decrypted_data = self.rsa.decrypt_ecb(decompressed_data)
        else:
            raise ValueError(f"Unsupported mode {self.mode}")
        self.decrypted_compressed_data = self._compress_idat(decrypted_data)

    def save_png(self, output_file, encrypted=True):
        """
        Zapisuje zaszyfrowany lub odszyfrowany plik PNG.

        :param output_file: Ścieżka do pliku wyjściowego.
        :param encrypted: Flaga wskazująca, czy zapisać zaszyfrowane czy odszyfrowane dane.
        """
        with open(output_file, "wb") as f_out:
            # Zapisanie sygnatury PNG
            PngSignature = b"\x89PNG\r\n\x1a\n"
            f_out.write(PngSignature)

            # Zapisanie wszystkich chunków oprócz IDAT i IEND
            for chunk_type, chunk_data in self.chunks:
                if chunk_type == b"IDAT":
                    data_to_write = (
                        self.encrypted_compressed_data
                        if encrypted
                        else self.decrypted_compressed_data
                    )
                    f_out.write(struct.pack(">I", len(data_to_write)))
                    f_out.write(chunk_type)
                    f_out.write(data_to_write)
                    crc = zlib.crc32(data_to_write, zlib.crc32(chunk_type))
                    f_out.write(struct.pack(">I", crc))
                elif chunk_type != b"IEND":
                    f_out.write(struct.pack(">I", len(chunk_data)))
                    f_out.write(chunk_type)
                    f_out.write(chunk_data)
                    crc = zlib.crc32(chunk_data, zlib.crc32(chunk_type))
                    f_out.write(struct.pack(">I", crc))

            # Zapisanie chunku IEND
            f_out.write(struct.pack(">I", 0))
            f_out.write(b"IEND")
            crc = zlib.crc32(b"IEND")
            f_out.write(struct.pack(">I", crc))


# Przykład użycia
rsa = RSA(key_size=2024)  # 1024 2048

modes = ["ECB", "OFB", "CTR", "CFB"]  # "ECB", "OFB", "CTR", "CFB"

# Upewnij się, że katalogi istnieją
os.makedirs("encrypted", exist_ok=True)
os.makedirs("decrypted", exist_ok=True)

for m in modes:
    encryptor = PNGEncryptor(rsa, mode=m)
    encryptor.read_png("white.png")
    iv = get_random_bytes(16)  # Wektor inicjalizujący
    nonce = (
        get_random_bytes(16) if m == "CTR" else None
    )  # Generuj nonce tylko dla trybu CTR

    encrypted_path = f"encrypted/encrypted_{m}_white_2048.png"
    decrypted_path = f"decrypted/decrypted_{m}_white_2048.png"

    if m == "CTR":
        encryptor.encrypt_idat(
            iv, nonce
        )  # Przekaż zarówno IV, jak i nonce dla trybu CTR
    else:
        encryptor.encrypt_idat(iv)  # Przekaż tylko IV dla innych trybów

    encryptor.save_png(encrypted_path, encrypted=True)

    decryptor = PNGEncryptor(rsa, mode=m)
    decryptor.read_png(encrypted_path)
    if m == "CTR":
        decryptor.decrypt_idat(
            iv, nonce
        )  # Przekaż zarówno IV, jak i nonce dla trybu CTR
    else:
        decryptor.decrypt_idat(iv)  # Przekaż tylko IV dla innych trybów

    decryptor.save_png(decrypted_path, encrypted=False)
