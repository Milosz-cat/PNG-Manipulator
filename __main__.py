import os

import reader
import metadata

# For Hist
import matplotlib.pyplot as plt
import numpy as np



def main():

    # Pierwsza część projektu

    # # png_image_name = "monkey"  # "square"  # "monkey"

    # # # Dodanie chunków tekstowego i czasowego do obrazu
    # # metadata_editor = metadata.MetadataEditor(png_image_name + ".png")
    # # output_png_file = (
    # #     f"{png_image_name}_with_metadata" + ".png"
    # # )  # f"{png_image_name}_with_metadata" + ".png"  #png_image_name + ".png"

    # # metadata_editor.add_text_and_time_chunk(
    # #     "Author", "John Doe", 2023, 1, 1, 12, 0, 0, output_png_file
    # # )

    # # # Dodanie chunka Hist
    # # histogram, colors = metadata_editor.quantize_image_colors(
    # #     output_png_file, num_colors=16
    # # )

    # # metadata_editor.add_hist_chunk(histogram, output_png_file)

    # # ciekawe zjawisko opowiedz prowadzacemu
    # # metadata_editor.add_hist_chunk(histogram, output_png_file)
    # # metadata_editor.add_hist_chunk(histogram, output_png_file)
    # # metadata_editor.add_hist_chunk(histogram, output_png_file)
    # # metadata_editor.add_hist_chunk(histogram, output_png_file)
    # # metadata_editor.add_hist_chunk(histogram, output_png_file)

    # # Wyświetlanie palety kolorów
    # # plt.figure(figsize=(10, 2))
    # # for i, color in enumerate(colors):
    # #     plt.fill_between([i, i + 1], 0, 1, color=np.array(color) / 255)
    # # plt.xlim(0, 16) #2
    # # plt.axis("off")
    # # plt.title("Paleta Kolorów")
    # # plt.show()

    # # Dodanie tła w skali szarości
    # # metadata_editor.add_background_color("greyscale", 128, output_png_file)
    # # Dodanie tła w kolorze RGB
    # #metadata_editor.add_background_color("rgb", (255, 0, 0), output_png_file)
    # # Dodanie tła w kolorze RGBA (uwaga: kanał alfa może być ignorowany przez niektóre czytniki PNG)

    # metadata_editor.add_background_color("rgba", (0, 255, 0, 255), output_png_file)

    # # Tworzenie instancji PNGReader dla oryginalnego obrazu
    # png_reader = reader.PNGReader(output_png_file)

    # # Parsowanie pliku PNG w celu odczytu metadanych
    # png_reader.parse()

    # # Wyświetlenie metadanych przed anonimizacją
    # print("Metadata before anonymization:")
    # print(png_reader.image_properties)

    # # Anonimizacja pliku PNG i zapisanie jako nowy plik
    # png_reader.anonymize_png()

    # # Wyświetlenie widma Fourierowskiego oryginalnego obrazu
    # # png_reader.display_fft_spectrum()

    # # Testowanie transformacji Fourierowskiej dla oryginalnego obrazu
    # # png_reader.test_fft_transformations()

    # # Tworzenie nowej instancji reader.PNGReader dla anonimizowanego obrazu
    # anon_png_reader = reader.PNGReader(png_reader.anonymized_file_path)

    # # Parsowanie pliku PNG w celu odczytu metadanych po anonimizacji
    # anon_png_reader.parse()

    # # Wyświetlenie metadanych po anonimizacji
    # print("Metadata after anonymization:")
    # print(anon_png_reader.image_properties)

    # # Wyświetlenie widma Fourierowskiego anonimizowanego obrazu
    # # anon_png_reader.display_fft_spectrum()

    # # Testowanie transformacji Fourierowskiej dla anonimizowanego obrazu
    # # anon_png_reader.test_fft_transformations()

    # Druga część projektu w osobonych plikach
    pass

if __name__ == "__main__":
    main()
