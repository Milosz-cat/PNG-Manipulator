import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm

# Do testowania Furiera
from scipy.ndimage import shift, rotate
from numpy.fft import fft2, ifft2, fftshift


class FourierTransform:
    """
    Klasa FourierTransform wykonuje operacje związane z transformacją Fouriera,
    umożliwiając analizę widma amplitudowego i fazowego obrazu oraz testowanie
    zachowania obrazu podczas przekształceń przestrzennych, takich jak przesunięcie i obrót.
    """

    def __init__(self, image_array):
        """
        Inicjalizuje klasę z tablicą obrazu.

        :param image_array: Dwuwymiarowa tablica NumPy reprezentująca obraz.
        """
        self.image_array = image_array

    def display_fft_spectrum(self):
        """
        Wyświetla widmo amplitudowe i fazowe obrazu za pomocą transformacji Fouriera.
        """
        # Wykonanie transformacji Fouriera na obrazie.
        fft_result = np.fft.fft2(self.image_array)
        fft_shifted = np.fft.fftshift(fft_result)

        # Obliczenie widma amplitudowego i fazowego.
        amplitude_spectrum = np.abs(fft_shifted)
        phase_spectrum = np.angle(fft_shifted)

        # Wyświetlanie widm.
        plt.figure(figsize=(12, 6))

        plt.subplot(1, 2, 1)
        plt.imshow(amplitude_spectrum, norm=LogNorm(vmin=5), cmap="gray")
        plt.colorbar()
        plt.title("Widmo amplitudowe")

        plt.subplot(1, 2, 2)
        plt.imshow(phase_spectrum, cmap="gray")
        plt.colorbar()
        plt.title("Widmo fazowe")

        plt.show()

    def display_shift_spectrums(self):
        plt.figure(figsize=(12, 8))

        # Oryginalne widmo amplitudowe
        plt.subplot(3, 2, 1)
        plt.imshow(self.image_array, cmap="gray")
        plt.title("Oryginalny obraz")

        plt.subplot(3, 2, 2)
        plt.imshow(
            np.abs(fftshift(fft2(self.image_array))), norm=LogNorm(vmin=5), cmap="gray"
        )
        plt.title("Widmo amplitudowe oryginału")

        # Przesunięcie z czarnym wypełnieniem
        plt.subplot(3, 2, 3)
        plt.imshow(
            shift(
                self.image_array,
                shift=[0, self.image_array.shape[1] / 2],
                mode="constant",
                cval=0,
            ),
            cmap="gray",
        )
        plt.title("Przesunięty obraz (czarne)")

        plt.subplot(3, 2, 4)
        plt.imshow(
            np.abs(
                fftshift(
                    fft2(
                        shift(
                            self.image_array,
                            shift=[0, self.image_array.shape[1] / 2],
                            mode="constant",
                            cval=0,
                        )
                    )
                )
            ),
            norm=LogNorm(vmin=5),
            cmap="gray",
        )
        plt.title("Widmo po przesunięciu (czarne)")

        # Przesunięcie z trybem "wrap"
        plt.subplot(3, 2, 5)
        plt.imshow(
            shift(self.image_array, shift=[0, self.image_array.shape[1] / 2], mode="wrap"),
            cmap="gray",
        )
        plt.title("Przesunięty obraz (wrap)")

        plt.subplot(3, 2, 6)
        plt.imshow(
            np.abs(
                fftshift(
                    fft2(
                        shift(
                            self.image_array,
                            shift=[0, self.image_array.shape[1] / 2],
                            mode="wrap",
                        )
                    )
                )
            ),
            norm=LogNorm(vmin=5),
            cmap="gray",
        )
        plt.title("Widmo po przesunięciu (wrap)")

        plt.tight_layout()
        plt.show()

    def create_tiled_image(self, tile_shape=(3, 3)):
        """
        Tworzy większy obraz poprzez powielenie oryginalnego obrazu w układzie tile_shape.
        """
        return np.tile(self.image_array, tile_shape)

    def display_rotation_spectrums(self):
        plt.figure(figsize=(12, 8))

        # Oryginalne widmo amplitudowe
        plt.subplot(3, 2, 1)
        plt.imshow(self.image_array, cmap="gray")
        plt.title("Oryginalny obraz")

        plt.subplot(3, 2, 2)
        plt.imshow(np.abs(fftshift(np.fft.fft2(self.image_array))), norm=LogNorm(vmin=5), cmap="gray")
        plt.title("Widmo amplitudowe oryginału")

        # Obrót z czarnym wypełnieniem, z zachowaniem rozmiaru
        rotated_image_constant = rotate(self.image_array, angle=22.5, reshape=True, mode="constant", cval=0)
        plt.subplot(3, 2, 3)
        plt.imshow(rotated_image_constant, cmap="gray")
        plt.title("Obrócony obraz (czarne)")

        plt.subplot(3, 2, 4)
        plt.imshow(np.abs(fftshift(np.fft.fft2(rotated_image_constant))), norm=LogNorm(vmin=5), cmap="gray")
        plt.title("Widmo po obróceniu (czarne)")

        # Tworzenie powielonego obrazu i obrót
        tiled_image = self.create_tiled_image()
        rotated_tiled_image = rotate(tiled_image, angle=22.5, reshape=False)

        # Wycinanie centralnej części
        center = np.array(rotated_tiled_image.shape) // 2
        original_shape = self.image_array.shape
        cropped_image = rotated_tiled_image[center[0]-original_shape[0]//2:center[0]+original_shape[0]//2, center[1]-original_shape[1]//2:center[1]+original_shape[1]//2]

        plt.subplot(3, 2, 5)
        plt.imshow(cropped_image, cmap="gray")
        plt.title("Obrócony obraz (tilted)")

        plt.subplot(3, 2, 6)
        plt.imshow(np.abs(fftshift(np.fft.fft2(cropped_image))), norm=LogNorm(vmin=5), cmap="gray")
        plt.title("Widmo po obróceniu (tilted)")

        plt.tight_layout()
        plt.show()

    def test_fft_transformations(self):
        self.display_shift_spectrums()
        self.display_rotation_spectrums()
