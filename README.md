## Message Encryption and Decryption Application

This application provides a simple and user-friendly interface for encrypting and decrypting text messages. It utilizes AES (Advanced Encryption Standard) with a 256-bit key for robust security.

### Features
- Encrypt text messages with AES 256-bit encryption.
- Decrypt previously encrypted messages.
- User-friendly GUI built with Tkinter.
- Secure password-based access to encryption and decryption functions.

### Requirements
- Python 3.x
- Tkinter (usually comes pre-installed with Python)
- Cryptography library

### Installation

1. Ensure Python 3.x is installed on your system.
2. Install the required cryptography library:

   ```
   pip install cryptography
   ```

3. Clone or download this repository to your local machine.

### Usage

1. Run the application:

   ```
   python main.py
   ```

2. Enter the text you want to encrypt or decrypt in the provided text field.
3. Enter the secret key "1234" for encryption and decryption.
4. Click on "ENCRYPT" to encrypt the text or "DECRYPT" to decrypt the text.
5. The encrypted or decrypted text will be displayed in a new window.

### GIF Demo

![Encryption and Decryption Demo](https://media.giphy.com/media/eSsHEv0vzMb21GlcuQ/giphy-downsized.gif)

### Note
For demonstration purposes, the application uses a hardcoded secret key ("1234"). In a real-world application, it is recommended to implement a more secure method for handling encryption keys.

### Contributions

Feel free to contribute or suggest improvements to this project. Your feedback and contributions are welcome!
