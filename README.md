# encrypt-decrypt-tool
# Encryption Tool

A modern, user-friendly desktop application for encrypting and decrypting text or files using AES, DES, and RSA algorithms. Built with Python and Tkinter, it features a clean GUI, dark/light mode toggle, and support for both text and file encryption.

## Features
- **AES, DES, and RSA encryption/decryption**
- **Encrypt/Decrypt text or files**
- **Save output to file**
- **Dark/Light mode toggle**
- **Minimalist, intuitive interface**

## Installation
1. Clone or download this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   or install manually 
   
   pip install tkinter
   pip install cryptography
   pip install pycryptodome 

## Usage
1. Run the tool:
   ```bash
   python encryption_tool.py
   ```
2. Choose input type (Text or File).
3. Enter or browse for your input.
4. Select encryption type (AES, DES, RSA).
5. Enter a key/password (not required for RSA encryption).
6. Click **Encrypt** or **Decrypt**.
7. Save the output if desired.

## Notes
- For best experience, place an optional `lock_icon.png` in the same directory for a custom window icon.
- Requires Python 3.7 or higher.
- Uses `pycryptodome` for cryptographic operations.

## License
MIT License 
