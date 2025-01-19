from PIL import Image
import numpy as np
import zlib
import struct


class MetadataEditor:
    """
    Klasa służąca do edycji metadanych plików PNG przez dodawanie specyficznych chunków,
    takich jak tEXt (tekstowe informacje), tIME (data i czas ostatniej modyfikacji) oraz HIST(histogram występowania kolorów)
    """
    def __init__(self, file_path):
        self.file_path = file_path

    @staticmethod
    def quantize_image_colors(image_path, num_colors=16):
        """
        Ładuje obraz, kwantyzuje kolory, generuje histogram i wyświetla paletę kolorów.
        :param image_path: Ścieżka do obrazu PNG.
        :param num_colors: Liczba kolorów do redukcji.
        :return: Histogram zkwantyzowanych kolorów i paleta kolorów.
        """
        # Wczytanie i kwantyzacja obrazu
        img = Image.open(image_path)
        img_quantized = img.quantize(colors=num_colors)
        img_data = np.array(img_quantized)

        # Generowanie histogramu
        histogram, _ = np.histogram(img_data, bins=num_colors, range=(0, num_colors - 1))
        histogram_scaled = np.interp(
            histogram, (histogram.min(), histogram.max()), (0, 65535)
        ).astype(int)

        # Pobieranie palety kolorów
        palette = img_quantized.getpalette()[
            : num_colors * 3
        ]  # Pobranie pierwszych 'num_colors' kolorów
        colors = [tuple(palette[i : i + 3]) for i in range(0, len(palette), 3)]

        return histogram_scaled, colors

    def add_hist_chunk(self, histogram, output_file_path):
        """
        Dodaje chunk hIST do pliku PNG na podstawie histogramu.
        """
        hist_chunk = self._prepare_hist_chunk(histogram)

        with open(self.file_path, "rb") as original_file:
            original_data = original_file.read()
            iend_index = original_data.rfind(b"IEND")

            if iend_index == -1:
                print("Nie znaleziono chunka IEND.")
                return

            new_data = (
                original_data[: iend_index - 4]
                + hist_chunk
                + original_data[iend_index - 4 :]
            )

        with open(output_file_path, "wb") as modified_file:
            modified_file.write(new_data)

        print(
            f"Zmodyfikowany plik PNG zapisany jako {output_file_path} z dodanym chunkiem hIST."
        )

    @staticmethod
    def _prepare_hist_chunk(histogram):
        """
        Przygotowuje dane chunka hIST.
        """
        hist_data = b"".join([struct.pack(">H", freq) for freq in histogram])
        hist_chunk_type = b"hIST"
        hist_crc = zlib.crc32(hist_chunk_type + hist_data)
        hist_chunk = (
            struct.pack(">I", len(hist_data))
            + hist_chunk_type
            + hist_data
            + struct.pack(">I", hist_crc)
        )
        return hist_chunk

    def add_text_and_time_chunk(
        self, keyword, text, year, month, day, hour, minute, second, output_file_path
    ):
        """
        Dodaje do pliku PNG chunki tEXt i tIME na podstawie dostarczonych danych.
        """
        text_chunk = self._prepare_text_chunk(keyword, text)
        time_chunk = self._prepare_time_chunk(year, month, day, hour, minute, second)

        with open(self.file_path, "rb") as original_file:
            original_data = original_file.read()
            # Szukamy indeksu, gdzie zaczyna się chunk IEND.
            iend_index = original_data.rfind(b"IEND")

            if iend_index == -1:
                new_data = original_data  # Jeśli nie znajdziemy IEND, zachowujemy oryginalne dane.
            else:
                # Wstawiamy nowe chunki przed IEND.
                new_data = (
                    original_data[: iend_index - 4]
                    + text_chunk
                    + time_chunk
                    + original_data[iend_index - 4 :]
                )

        with open(output_file_path, "wb") as new_file:
            new_file.write(new_data)

        print(
            f"Modified PNG saved as {output_file_path} with an added tEXt and tIME chunk."
        )

    @staticmethod
    def _prepare_text_chunk(keyword, text):
        """
        Przygotowuje dane chunka tEXt.
        """
        text_chunk_data = keyword.encode("latin-1") + b"\x00" + text.encode("latin-1")
        text_chunk_type = b"tEXt"
        text_crc = zlib.crc32(text_chunk_type + text_chunk_data)
        text_chunk = (
            struct.pack(">I", len(text_chunk_data))
            + text_chunk_type
            + text_chunk_data
            + struct.pack(">I", text_crc)
        )
        return text_chunk

    @staticmethod
    def _prepare_time_chunk(year, month, day, hour, minute, second):
        """
        Przygotowuje dane chunka tIME.
        """
        time_chunk_data = struct.pack(">HBBBBB", year, month, day, hour, minute, second)
        time_chunk_type = b"tIME"
        time_crc = zlib.crc32(time_chunk_type + time_chunk_data)
        time_chunk = (
            struct.pack(">I", len(time_chunk_data))
            + time_chunk_type
            + time_chunk_data
            + struct.pack(">I", time_crc)
        )
        return time_chunk

    def add_background_color(self, color_type, color, output_file_path):
        """
        Dodaje chunk bKGD z kolorem tła do pliku PNG.
        :param color_type: Typ koloru ('palette', 'greyscale', 'rgb', 'rgba')
        :param color: Kolor w formacie odpowiednim dla color_type
        :param output_file_path: Ścieżka do pliku wyjściowego
        """
        if color_type == "greyscale":
            bkgd_chunk = self._prepare_bkgd_chunk_greyscale(color)
        elif color_type == "rgb":
            bkgd_chunk = self._prepare_bkgd_chunk_rgb(color)
        elif color_type == "rgba":
            bkgd_chunk = self._prepare_bkgd_chunk_rgba(color)
        else:
            raise ValueError("Nieznany typ koloru tła.")

        # Dodanie chunka bKGD do pliku PNG
        self._add_chunk_to_png(bkgd_chunk, output_file_path)

    def _create_chunk(self, chunk_type, data):
        chunk_length = len(data)
        chunk_type_encoded = chunk_type.encode("ascii")
        crc = zlib.crc32(chunk_type_encoded + data) & 0xFFFFFFFF  # Obliczenie CRC
        return (
            struct.pack(">I4s", chunk_length, chunk_type_encoded)
            + data
            + struct.pack(">I", crc)
        )

    def _add_chunk_to_png(self, chunk, output_file_path):
        with open(self.file_path, "rb") as original_png:
            original_data = original_png.read()
        iend_position = original_data.rfind(b"IEND")

        # Tworzenie nowych danych PNG z dodanym chunkiem bKGD przed IEND
        modified_data = (
            original_data[: iend_position - 4]
            + chunk
            + original_data[iend_position - 4 :]
        )

        # Zapis zmodyfikowanych danych do nowego pliku
        with open(output_file_path, "wb") as modified_png:
            modified_png.write(modified_data)

    def _prepare_bkgd_chunk_greyscale(self, greyscale_value):
        """
        Przygotowanie danych chunka bKGD dla skali szarości.
        :param greyscale_value: Wartość koloru tła w skali szarości (0-65535)
        """
        # Zakładamy, że 'greyscale_value' jest w odpowiednim zakresie
        bkgd_data = struct.pack(">H", greyscale_value)
        return self._create_chunk("bKGD", bkgd_data)

    def _prepare_bkgd_chunk_rgb(self, rgb_value):
        """
        Przygotowanie danych chunka bKGD dla RGB.
        :param rgb_value: Krotka z wartościami RGB (r, g, b), każda w zakresie (0-255)
        """
        r, g, b = rgb_value
        bkgd_data = struct.pack(">HHH", r, g, b)
        return self._create_chunk("bKGD", bkgd_data)

    def _prepare_bkgd_chunk_rgba(self, rgba_value):
        """
        Ta metoda nie jest dokładnie zgodna z formatem PNG, ponieważ chunk bKGD nie obsługuje bezpośrednio RGBA,
        ale pokazuje, jak można by przekształcić RGBA na RGB poprzez ignorowanie kanału alfa.
        :param rgba_value: Krotka z wartościami RGBA (r, g, b, a), każda w zakresie (0-255)
        """
        r, g, b, a = rgba_value
        bkgd_data = struct.pack(">HHHH", r, g, b, a)
        return self._create_chunk("bKGD", bkgd_data)
