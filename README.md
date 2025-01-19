# PNG-Manipulator
PNG Manipulator a set of programs written in Python to manipulate PNG files, enabling encryption (RSA, AES), metadata editing, anonymization and Fourier spectrum analysis. The project offers support for PNG chunks such as tEXt, tIME, IDAT, and enables data visualization for analytical and security purposes.

## Project Description

This project combines two tasks:
1. **PNG File Analysis**: Reading and manipulating metadata, Fourier transformation, and data anonymization.
2. **Data Encryption Using RSA**: Encrypting PNG data chunks while maintaining file integrity and comparing different encryption methods.

### Task 1: PNG File Analysis
- Read and display the contents of essential PNG segments (IHDR, IDAT, IEND).
- Remove additional ancillary chunks for anonymization purposes.
- Display the Fourier spectrum of images and visualize geometric transformations (shift, rotation).
- Test the correctness of Fourier transformations.
- Remove unnecessary metadata without modifying the image content.

### Task 2: Data Encryption Using RSA
- Encrypt IDAT chunks using the RSA algorithm in ECB and CBC modes.
- Use OAEP padding for enhanced security.
- Test encryption on both decompressed and compressed data.
- Compare the results of implemented RSA encryption with standard library results.

## Implemented Features

### 1. Data Encryption (Files: `rsa_encrypt.py`, `rsa_encrypt_lib.py`, `rsa_encrypt_compress.py`)
- **RSA Implementation**: Support for ECB and CBC modes with OAEP padding.
- **Hybrid Encryption**: Combination of RSA (to encrypt session keys) and AES (to encrypt data).
- **IDAT Chunk Encryption**: Encrypts and decrypts PNG image data while retaining file compatibility.

### 2. PNG File Manipulation (Files: `chunks.py`, `metadata.py`, `anonymize.py`, `reader.py`)
- **Chunk Handling**: Parsing and modifying chunks such as IHDR, IDAT, tEXt, tIME.
- **Data Anonymization**: Removing unnecessary chunks to protect metadata.
- **Adding Metadata**: Insert custom metadata into PNG files, such as histograms and timestamps.

### 3. Fourier Transformation (Files: `fourier.py`, `reader.py`)
- **Spectrum Analysis**: Compute and display amplitude and phase spectra of images.
- **Transformation Testing**: Analyze the effects of geometric transformations (e.g., shifting, rotation) on the Fourier spectrum.

### 4. Information Hiding (Files: `chunks.py`, `metadata.py`, `anonymize.py`)
- **Chunk Manipulation**: Embed data within histogram and IDAT chunk structures.
- **Steganography in PNG Filters**: Encode data by manipulating the filter types used for each line of the image.

### 5. Testing (Folder: `tests/`)
- Comprehensive tests confirm the correctness of implemented features.
- Testing scripts validate functionalities, such as encryption, anonymization, and Fourier analysis.

## Project Structure


```plaintext
.
├── PNG-Manipulator/              # Source code
│   ├── rsa_encrypt.py            # RSA encryption
│   ├── rsa_encrypt_lib.py        # Hybrid encryption (RSA + AES)
│   ├── rsa_encrypt_compress.py   # RSA with compression support
│   ├── anonymize.py              # PNG anonymization
│   ├── chunks.py                 # PNG chunk handling
│   ├── metadata.py               # Metadata manipulation
│   ├── fourier.py                # Fourier transformation
│   ├── reader.py                 # Main class for PNG handling
│   ├── __main__.py               # Main application entry point
│   ├── tests/                    # Unit tests to validate project functionality
│   ├── sample_img/               # Sample PNG files for testing
│   ├── README.md                 # Project documentation
│   ├── LICENSE                   # License file
│   ├── requirements.txt          # Dependency list
│   └── .gitignore                # Git ignore rules


## Installation and Usage

### 1. Clone the repository
```bash
git clone <repository_url>
cd <project_directory>

### 2. Create and activate a virtual environment
```bash
python -m venv venv
source venv/bin/activate          # On Windows: venv\Scripts\activate

### 3. Install dependencies
```bash
pip install -r requirements.txt

### 4. Run the project
```bash
python __main__.py

## Further Reading

For those interested in understanding more about the PNG format, its chunks, and related topics, here are some useful resources:

**Overview of the PNG File Format - PNG (Portable Network Graphics) Specification**
-   [1. Introduction](https://www.w3.org/TR/PNG-Introduction.html)
-   [2. Data Representation](https://www.w3.org/TR/PNG-DataRep.html)
-   [3. File Structure](https://www.w3.org/TR/PNG-Structure.html)
-   [4. Chunk Specifications](https://www.w3.org/TR/PNG-Chunks.html)
