import zlib
import struct


class Anonymizer:
    """
    Klasa Anonymizer służy do anonimizacji plików PNG poprzez usunięcie nieistotnych chunków.
    Zachowuje tylko niezbędne chunki, takie jak IHDR, IDAT i IEND, które są kluczowe dla
    struktury pliku PNG, usuwając wszystkie inne chunki, które mogą zawierać informacje
    identyfikujące lub niepotrzebne metadane.
    """

    def __init__(self, input_file_path, output_file_suffix="_anonymized"):
        self.input_file_path = input_file_path
        self.output_file_path = input_file_path.replace(
            ".png", f"{output_file_suffix}.png"
        )

    def anonymize_png(self):
        """
        Funkcja przetwarza plik PNG wejściowy, zachowując tylko niezbędne chunki
        (IHDR, IDAT, IEND), i zapisuje wynikowy, anonimizowany plik PNG.
        """
        # Zdefiniowanie typów chunków, które zostaną zachowane w anonimizowanym pliku.
        essential_chunk_types = {"IHDR", "IDAT", "IEND"}

        with open(self.input_file_path, "rb") as input_file, open(
            self.output_file_path, "wb"
        ) as output_file:
            # Kopiowanie sygnatury pliku PNG.
            output_file.write(input_file.read(8))

            while True:
                # Odczyt długości aktualnego chunka.
                chunk_length_bytes = input_file.read(4)
                if len(chunk_length_bytes) == 0:
                    break  # Koniec pliku
                chunk_length = struct.unpack(">I", chunk_length_bytes)[0]

                chunk_type = input_file.read(4).decode("ascii")

                chunk_data = input_file.read(chunk_length)

                # Pomijanie odczytu CRC, które zostanie wygenerowane na nowo dla zachowanych chunków.
                input_file.read(4)

                if chunk_type in essential_chunk_types:
                    output_file.write(chunk_length_bytes)
                    output_file.write(chunk_type.encode("ascii"))
                    output_file.write(chunk_data)
                    # Generowanie nowego CRC na podstawie typu chunka i jego danych.
                    new_crc = zlib.crc32(chunk_type.encode("ascii") + chunk_data)
                    # Zapis nowego CRC do pliku wyjściowego.
                    output_file.write(struct.pack(">I", new_crc))
