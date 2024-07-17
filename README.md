# OpenCryptUI

OpenCryptUI is a Qt-based graphical user interface application for file and folder encryption. It supports various encryption algorithms and key derivation functions.

## Features

- Encrypt and decrypt files and folders.
- Support for multiple encryption algorithms: AES-256-CBC, AES-256-GCM, AES-256-CTR, ChaCha20-Poly1305, Twofish, Serpent, Blowfish, Camellia, and AES-128-CBC.
- Support for multiple key derivation functions: PBKDF2, Argon2, and Scrypt.
- Option to enable HMAC integrity check.
- Memory encryption: Encrypts the in-memory keys used during encryption operations to protect against memory dump attacks.
- Keyfile support: Keyfiles can be used to provide an additional layer of security, ensuring that access requires both the correct password and one or multiple keyfiles.
- Hardware acceleration support: Detects support for hardware features like Intel AES-NI, which can potentially speed up AES encryption and decryption processes. OpenSSL may utilize these features automatically when available.

## Dependencies

- Qt 5 or later
- OpenSSL
- Libsodium
- Argon2
- CMake

## Building the Project

To build the project, follow these steps:

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd opencryptui
   ```

2. Create a build directory and navigate to it:
   ```bash
   mkdir build
   cd build
   ```

3. Run CMake to configure the project:
   ```bash
   cmake ..
   ```

4. Build the project using `make`:
   ```bash
   make
   ```

5. Run the application:
   ```bash
   ./EncryptionApp
   ```

## Usage

1. Launch the application:
   ```bash
   ./EncryptionApp
   ```

2. Use the "File Encryption" tab to encrypt or decrypt individual files:
   - Browse and select the file.
   - Enter the password.
   - Choose the encryption algorithm and key derivation function.
   - Set the number of iterations.
   - (Optional) Enable HMAC integrity check.
   - (Optional) Add one or multiple keyfiles.
   - Click "Encrypt" or "Decrypt".

3. Use the "Folder Encryption" tab to encrypt or decrypt entire folders:
   - Browse and select the folder.
   - Enter the password.
   - Choose the encryption algorithm and key derivation function.
   - Set the number of iterations.
   - (Optional) Enable HMAC integrity check.
   - (Optional) Add one or multiple keyfiles.
   - Click "Encrypt Folder" or "Decrypt Folder".

## Contributing

Contributions are welcome! If you find a bug or want to add a new feature, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Todo

OpenCryptUI aims to implement several additional features found in popular encryption tools like VeraCrypt. Here are some planned features:

- **Hidden volumes:** Create hidden encrypted volumes within an existing encrypted volume for plausible deniability.
- **PIM (Personal Iterations Multiplier) support:** Allow users to specify a PIM value to increase the number of iterations in the key derivation process for added security.
- **Explicit hardware acceleration utilization:** Implement and verify explicit use of hardware acceleration for all supported operations, with performance comparisons.
- **Cross-platform support:** Enhance compatibility and testing for various operating systems, including Windows, macOS, and Linux.
- **Secure wipe:** Implement secure deletion of original files after encryption to prevent data recovery.

Feel free to contribute to these features or suggest new ones!