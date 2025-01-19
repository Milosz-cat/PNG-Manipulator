import os
import struct
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class PNGEncryptor:
    def __init__(self, mode="CBC", key=None):
        self.mode = mode.upper()
        self.key = key if key else os.urandom(32)  # AES-256 key
        self.backend = default_backend()

    def read_png(self, file_path):
        self.chunks = []
        with open(file_path, "rb") as f:
            signature = f.read(8)  # Read and verify the PNG signature
            while True:
                chunk_length = struct.unpack(">I", f.read(4))[0]
                chunk_type = f.read(4)
                chunk_data = f.read(chunk_length)
                f.read(4)  # Skip the CRC
                self.chunks.append((chunk_type, chunk_data))
                if chunk_type == b"IEND":
                    break

        self.IDAT_data = b"".join(
            data for ctype, data in self.chunks if ctype == b"IDAT"
        )

    def encrypt_decrypt_idat(self, encrypt=True, iv=None):
        cipher = self.create_cipher(iv)
        encryptor = cipher.encryptor() if encrypt else cipher.decryptor()
        unpadder = (
            padding.PKCS7(algorithms.AES.block_size).unpadder() if not encrypt else None
        )
        padder = padding.PKCS7(algorithms.AES.block_size).padder() if encrypt else None

        data = self.IDAT_data
        if encrypt:
            data = padder.update(data) + padder.finalize()
        processed_data = encryptor.update(data) + encryptor.finalize()
        if not encrypt:
            processed_data = unpadder.update(processed_data) + unpadder.finalize()
        return processed_data

    def create_cipher(self, iv):
        if self.mode == "CBC":
            return Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def save_png(self, output_file, data):
        with open(output_file, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n")  # Write PNG signature
            for chunk_type, chunk_data in self.chunks:
                if chunk_type == b"IDAT":
                    new_length = len(data)
                    f.write(struct.pack(">I", new_length))
                    f.write(chunk_type)
                    f.write(data)
                    crc = zlib.crc32(chunk_type + data)
                    f.write(struct.pack(">I", crc))
                elif chunk_type != b"IEND":
                    f.write(struct.pack(">I", len(chunk_data)))
                    f.write(chunk_type)
                    f.write(chunk_data)
                    crc = zlib.crc32(chunk_type + chunk_data)
                    f.write(struct.pack(">I", crc))
            f.write(struct.pack(">I", 0))
            f.write(b"IEND")
            crc = zlib.crc32(b"IEND")
            f.write(struct.pack(">I", crc))


# Example Usage for Encryption and Decryption:
key = os.urandom(32)  # AES-256 bit key
iv = os.urandom(16)  # Initialization vector for CBC mode

# Initialize the encryptor with mode and key
encryptor = PNGEncryptor(mode="CBC", key=key)

# Encrypt the image
encryptor.read_png("white.png")
encrypted_data = encryptor.encrypt_decrypt_idat(encrypt=True, iv=iv)
encryptor.save_png("encrypted_image.png", encrypted_data)

# Initialize the decryptor with the same mode and key
decryptor = PNGEncryptor(mode="CBC", key=key)

# Decrypt the image
decryptor.read_png("encrypted_image.png")
decrypted_data = decryptor.encrypt_decrypt_idat(encrypt=False, iv=iv)
decryptor.save_png("decrypted_image.png", decrypted_data)
