import numpy as np
from PIL import Image

import zlib
import struct
import os

import chunks
import fourier
import anonymize


class PNGReader:
    """
    Klasa PNGReader służy do odczytu, analizy, modyfikacji i anonimizacji plików PNG.
    Zapewnia funkcjonalności takie jak parsowanie metadanych pliku, wyświetlanie widma
    Fourierowskiego obrazu, testowanie transformacji Fourierowskiej oraz anonimizacja pliku.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.metadata = {}  # Słownik przechowujący metadane odczytane z pliku
        self.image_array = None  # Tablica NumPy przechowująca obraz w skali szarości
        self.anonymized_file_path = self.file_path.replace(
            ".png", "_anonymized.png"
        )
        # Zdefiniowanie handlerów dla poszczególnych typów chunków
        self.handlers = {
            "IHDR": chunks.IHDRHandler,
            "pHYs": chunks.PHYSHandler,
            "tIME": chunks.TIMEHandler,
            "tEXt": chunks.TEXtHandler,
            "bKGD": chunks.BKGDHandler,
            "sRGB": chunks.SRGBHandler,
            "gAMA": chunks.GAMAHandler,
            "cHRM": chunks.CHRMHandler,
            "iCCP": chunks.ICCPHandler,
            "PLTE": chunks.PLTEHandler,
            "IDAT": chunks.IDATHandler,
            "IEND": chunks.IENDHandler,
            "hIST": chunks.HISTHandler,
            "tRNS": chunks.TRNSHandler,
            "zTXt": chunks.ZTXtHandler,
        }

    @property
    def image_properties(self):
        """
        Zwraca sformatowane informacje o metadanych obrazu.
        """
        properties = []
        for key, value in self.metadata.items():
            properties.append(f"{key}: {value}")
        return "\n".join(properties)

    def parse(self):
        """
        Parsuje plik PNG, odczytując metadane z chunków i przetwarzając obraz do tablicy NumPy.
        """
        with open(self.file_path, "rb") as file:
            self._read_and_process_chunks(file)
            # Odczyt obrazu i konwersja do skali szarości
            image = Image.open(self.file_path).convert("L")
            self.image_array = np.array(image)

    def _read_and_process_chunks(self, file):
        color_type = None  # Dodajemy zmienną do przechowywania typu koloru

        file.read(8)  # Pomijanie sygnatury PNG
        while True:
            chunk_length_bytes = file.read(4)
            if len(chunk_length_bytes) == 0:
                break  # Koniec pliku
            chunk_length = chunks.ChunkHandler.to_int(chunk_length_bytes)
            chunk_type = file.read(4).decode("ascii")
            chunk_data = file.read(chunk_length)
            file.read(4)  # Pomijanie CRC

            if chunk_type == "IHDR":
                ihdr_handler = chunks.IHDRHandler(chunk_data)
                ihdr_data = ihdr_handler.parse()
                color_type = ihdr_data['color_type']  # Zapisujemy typ koloru z chunka IHDR
                self.metadata[chunk_type] = ihdr_data

            elif chunk_type == "bKGD" and color_type is not None:
                bkgd_handler = self.handlers["bKGD"](chunk_data)  # Tworzymy instancję handlera bKGD
                self.metadata[chunk_type] = bkgd_handler.parse(color_type)  # Przekazujemy typ koloru do metody parse
                bkgd_handler.display_background_color(
                    color_type
                )  # Wywołanie metody display_background_color z typem koloru

            else:
                # Obsługa pozostałych chunków
                handler_class = self.handlers.get(chunk_type)
                if handler_class:
                    handler = handler_class(chunk_data)
                    self.metadata[chunk_type] = handler.parse()

                    if chunk_type == "hIST":
                        handler.display_histogram()  # Wywołanie metody display_histogram dla hISTHandler
                else:
                    self.metadata[chunk_type] = "Data not parsed"

    def display_fft_spectrum(self):
        """
        Wyświetla widmo Fourierowskie obrazu.
        """
        fourier.FourierTransform(self.image_array).display_fft_spectrum()

    def test_fft_transformations(self):
        """
        Testuje transformacje Fourierowskie na obrazie.
        """
        fourier.FourierTransform(self.image_array).test_fft_transformations()

    def anonymize_png(self):
        """
        Anonimizuje plik PNG, zachowując tylko niezbędne chunki.
        """
        anonymize.Anonymizer(self.file_path).anonymize_png()