import zlib
import struct

# For Hist
import matplotlib.pyplot as plt
import matplotlib.patches as patches


class ChunkHandler:
    """
    Klasa bazowa dla obsługi chunków w formacie PNG. Każdy chunk składa się z kilku
    elementów: długości, typu, danych i kodu CRC. Ta klasa zapewnia wspólne metody
    i strukturę dla konkretnych handlerów chunków.
    """

    def __init__(self, data):
        self.data = data

    @staticmethod
    def to_int(bytes_sequence):
        return int.from_bytes(bytes_sequence, byteorder="big")

    def parse(self):
        raise NotImplementedError("Subclass must implement abstract method")


class IHDRHandler(ChunkHandler):
    """
    Handler dla chunka IHDR, który zawiera podstawowe informacje o obrazie PNG,
    w tym jego wymiary (szerokość i wysokość), głębię bitową, typ koloru,
    metodę kompresji, metodę filtracji i metodę przeplotu.
    """

    def parse(self):
        info = {
            "width": self.to_int(self.data[:4]),
            "height": self.to_int(self.data[4:8]),
            "bit_depth": self.data[8],
            "color_type": self.data[9],
            "compression_method": self.data[10],
            "filter_method": self.data[11],
            "interlace_method": self.data[12],
        }
        return info


class PLTEHandler(ChunkHandler):
    """
    Handler dla chunka PLTE, który definiuje paletę kolorów używaną w obrazach
    z indeksowanymi kolorami. Chunk PLTE zawiera listę kolorów, gdzie każdy kolor
    reprezentowany jest przez trzy bajty (czerwony, zielony, niebieski).
    """

    def parse(self):
        colors = []
        num_colors = len(self.data) // 3
        for i in range(num_colors):
            r = self.data[i * 3]
            g = self.data[i * 3 + 1]
            b = self.data[i * 3 + 2]
            colors.append((r, g, b))
        return {"palette_colors": colors}


class IDATHandler(ChunkHandler):
    """
    Handler dla chunków IDAT, które zawierają faktyczne dane obrazu.
    Dane te są skompresowane przy użyciu algorytmu DEFLATE.
    """

    def parse(self):
        # Handle compressed image data
        return {"compressed_image_data": "Handle compressed image data appropriately"}


class IENDHandler(ChunkHandler):
    def parse(self):
        # IEND chunk doesn't carry any data, simply indicates end of PNG file
        return {}


class PHYSHandler(ChunkHandler):
    """
    Handler dla chunka pHYs, który zawiera informacje o fizycznych wymiarach piksela,
    określającymi zamierzone proporcje wyświetlania obrazu. Dane w tym chunku pozwalają
    na określenie rozmiaru piksela w osiach x i y, co jest przydatne do poprawnego
    skalowania obrazu na urządzeniach wyświetlających.

    Chunk pHYs może być używany do zapewnienia, że obraz będzie wyświetlany w prawidłowych
    proporcjach, nawet jeśli środowisko docelowe nie obsługuje bezpośrednio metadanych o rozmiarze piksela.

    Struktura danych chunka pHYs:
    - pixels_per_unit_x: liczba pikseli na jednostkę (np. metr) w osi x,
    - pixels_per_unit_y: liczba pikseli na jednostkę (np. metr) w osi y,
    - unit_specifier: specyfikator jednostki, gdzie 0 oznacza, że jednostka jest nieznana,
      a 1 wskazuje na metr jako jednostkę miary.
    """

    def parse(self):
        pixels_per_unit_x = self.to_int(self.data[:4])
        pixels_per_unit_y = self.to_int(self.data[4:8])
        unit_specifier = self.data[8]
        return {
            "pixels_per_unit_x": pixels_per_unit_x,
            "pixels_per_unit_y": pixels_per_unit_y,
            "unit_specifier": unit_specifier,  # 0: unknown, 1: meter
        }


class TIMEHandler(ChunkHandler):
    """
    Handler dla chunka tIME, który przechowuje czas ostatniej modyfikacji pliku,
    zapewniając rok, miesiąc, dzień, godzinę, minutę i sekundę.
    """

    def parse(self):
        year = self.to_int(self.data[:2])
        month, day, hour, minute, second = struct.unpack(">BBBBB", self.data[2:])
        return {
            "year": year,
            "month": month,
            "day": day,
            "hour": hour,
            "minute": minute,
            "second": second,
        }


class TEXtHandler(ChunkHandler):
    """
    Handler dla chunków tEXt, które zawierają tekstowe informacje o obrazie,
    takie jak tytuł, autor, opis, itp. Chunk tEXt składa się z pary klucz-wartość.
    """

    def parse(self):
        try:
            keyword, text = self.data.split(b"\x00", 1)
            return {
                "keyword": keyword.decode("iso-8859-1"),
                "text": text.decode("iso-8859-1"),
            }
        except ValueError:
            return {"error": "Invalid tEXt chunk"}


class BKGDHandler(ChunkHandler):
    """
    Handler dla chunka bKGD, który dostarcza domyślny kolor tła obrazu.
    Format danych zależy od typu obrazu (np. indeksowany, skala szarości, RGB).
    """

    def parse(self, color_type):
        if color_type == 0:
            # grayscale
            return {"background": self.to_int(self.data)}
        elif color_type == 2:
            # RGB
            r = self.to_int(self.data[:2])
            g = self.to_int(self.data[2:4])
            b = self.to_int(self.data[4:6])
            return {"background": (r, g, b)}
        elif color_type == 3:
            # indexed color
            palette_index = self.to_int(self.data)
            return {"palette_index": palette_index}
        elif color_type == 4:
            # grayscale with alpha channel
            gray = self.to_int(self.data[:2])
            alpha = self.to_int(self.data[2:])
            return {"background": (gray, alpha)}
        elif color_type == 6:
            # RGBA
            r = self.to_int(self.data[:2])
            g = self.to_int(self.data[2:4])
            b = self.to_int(self.data[4:6])
            alpha = self.to_int(self.data[6:])
            return {"background": (r, g, b, alpha)}
        else:
            return {"error": "Unsupported color type for background"}

    def display_background_color(self, color_type):
        """
        Wyświetla kolor tła za pomocą matplotlib.
        """
        bkgd_data = self.parse(color_type)
        color = bkgd_data["background"]

        # Dla RGB i RGBA, matplotlib oczekuje wartości kolorów w zakresie [0, 1]
        if isinstance(color, tuple):
            color = tuple(c / 255.0 for c in color)
        elif isinstance(color, int):
            # Dla skali szarości, konwertujemy wartość na zakres [0, 1] i tworzymy kolor w formacie RGB
            color = tuple([color / 255.0], 0, 0)

        # Tworzenie prostego wykresu z wyświetlonym kolorem tła
        fig, ax = plt.subplots()
        # Ustawienie tła dla obszaru wykresu
        fig.patch.set_facecolor(color)
        ax.add_patch(patches.Rectangle((0, 0), 1, 1, color=color))
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        plt.show()


class SRGBHandler(ChunkHandler):
    """
    Handler dla chunka sRGB, który informuje o przestrzeni kolorów obrazu
    i zamierzonym renderowaniu kolorów, zgodnie z międzynarodowym standardem sRGB.
    """

    def parse(self):
        rendering_intent = self.data[0]
        return {"rendering_intent": rendering_intent}


class GAMAHandler(ChunkHandler):
    """
    Handler dla chunka gAMA, który określa charakterystykę gamma obrazu,
    pozwalając na odpowiednią korekcję gamma podczas wyświetlania.
    """

    def parse(self):
        gamma = self.to_int(self.data) / 100000.0
        return {"gamma": gamma}


class CHRMHandler(ChunkHandler):
    """
    Handler dla chunka cHRM, który przechowuje informacje o chrominancji niezbędne do
    dokładnego odwzorowania kolorów w obrazie PNG. Chrominancja to parametry określające
    położenie kolorów podstawowych oraz białego punktu w przestrzeni barw CIE 1931 xy chromaticity.

    Chunk cHRM jest kluczowy w procesie zarządzania kolorem, pozwalając na precyzyjne
    określenie, jak kolor podstawowy i biały punkt są reprezentowane w przestrzeni barw.
    Dzięki temu możliwe jest zachowanie spójności kolorów między różnymi urządzeniami
    wyświetlającymi, które mogą mieć różne domyślne ustawienia wyświetlania barw.

    Struktura danych chunka cHRM zawiera współrzędne chrominancji dla:
    - Białego punktu (white_point_x, white_point_y),
    - Czerwonego koloru podstawowego (red_x, red_y),
    - Zielonego koloru podstawowego (green_x, green_y),
    - Niebieskiego koloru podstawowego (blue_x, blue_y).
    """

    def parse(self):
        # Improved parsing logic, calculating chromaticities
        white_point_x = self.to_int(self.data[:4])
        white_point_y = self.to_int(self.data[4:8])
        red_x = self.to_int(self.data[8:12])
        red_y = self.to_int(self.data[12:16])
        green_x = self.to_int(self.data[16:20])
        green_y = self.to_int(self.data[20:24])
        blue_x = self.to_int(self.data[24:28])
        blue_y = self.to_int(self.data[28:32])
        return {
            "white_point_x": white_point_x,
            "white_point_y": white_point_y,
            "red_x": red_x,
            "red_y": red_y,
            "green_x": green_x,
            "green_y": green_y,
            "blue_x": blue_x,
            "blue_y": blue_y,
        }


class ICCPHandler(ChunkHandler):
    """
    Handler dla chunka iCCP, który zawiera profil kolorów ICC,
    umożliwiający zarządzanie kolorem w sposób zgodny z międzynarodowymi standardami.
    Profil ICC jest zakodowany za pomocą algorytmu kompresji DEFLATE.
    """

    def parse(self):
        try:
            compressed_data = self.data.split(b"\x00", 1)[1][1:]
            icc_profile_data = zlib.decompress(compressed_data)
            return {"icc_profile": "Data decompressed and interpreted"}
        except Exception as e:
            return {"error": str(e)}


class HISTHandler(ChunkHandler):
    """
    Handler dla chunka hIST, który zawiera histogram obrazu, reprezentujący
    rozkład częstotliwości występowania kolorów w palecie.
    """

    def parse(self):
        histogram = [
            self.to_int(self.data[i : i + 2]) for i in range(0, len(self.data), 2)
        ]
        return {"histogram": histogram}

    def display_histogram(self):
        """
        Wyświetla histogram częstotliwości występowania kolorów w palecie.
        """
        histogram_data = self.parse()["histogram"]
        plt.figure(figsize=(10, 6))
        plt.bar(range(len(histogram_data)), histogram_data, color="grey")
        plt.title("Histogram Częstotliwości Kolorów w Palecie")
        plt.xlabel("Indeks Koloru w Palecie")
        plt.ylabel("Częstotliwość Występowania")
        plt.show()


class TRNSHandler(ChunkHandler):
    """
    Handler dla chunka tRNS, który zawiera informacje o alfa-kanale dla palety kolorów
    (przezroczystość poszczególnych kolorów w palecie) lub pojedynczą wartość przezroczystości
    dla obrazów w skali szarości.
    """

    def parse(self):
        transparency = self.data
        return {"transparency": transparency}


class ZTXtHandler(ChunkHandler):
    """
    Handler dla chunka zTXt, który zawiera skompresowane dane tekstowe. Składa się
    z klucza (keyword), metody kompresji i skompresowanego tekstu.
    """

    def parse(self):
        try:
            keyword, rest = self.data.split(b"\x00", 1)
            compression_method = rest[0]
            compressed_text = rest[1:]
            if compression_method == 0:  # Obecnie zlib jest jedyną akceptowaną metodą
                decompressed_text = zlib.decompress(compressed_text).decode(
                    "iso-8859-1"
                )
                return {
                    "keyword": keyword.decode("iso-8859-1"),
                    "text": decompressed_text,
                }
            else:
                return {"error": "Unsupported compression method"}
        except Exception as e:
            return {"error": str(e)}
