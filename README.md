# OpenCryptUI

OpenCryptUI is a Qt-based graphical user interface application for file and folder encryption. It supports various encryption algorithms and key derivation functions.

![Open Crypt UI](opencryptui.png)

## Features

- Encrypt and decrypt files, folders, and disk volumes.
- Support for multiple encryption algorithms: AES-256-CBC, AES-256-GCM, AES-256-CTR, ChaCha20-Poly1305, Camellia (128/256), AES-128-CBC, and others.
- Support for multiple key derivation functions: PBKDF2, Argon2, and Scrypt.
- Enforced authenticated encryption with HMAC / AEAD for integrity checks.
- Memory protection: Sensitive keys are securely erased from memory after use with constant-time operations.
- Advanced secure memory management: Memory locking (mlock) prevents sensitive data from being swapped to disk.
- Military-grade entropy sources: Multiple hardware and software random sources with continuous quality monitoring.
- Hardware RNG support: Utilizes RDSEED/RDRAND CPU instructions if available for true hardware entropy.
- Tamper-evident wrappers: Digital signatures and integrity verification to detect data tampering.
- Secure deletion: Multi-pass file wiping with full inode scrubbing to prevent data recovery.
- Keyfile support with domain separation: Cryptographically secure HMAC-based keyfile processing.
- Hardware acceleration support: Automatically detects AES-NI and other hardware features.
- Real-time entropy health monitoring with quality metrics and testing.
- Built-in benchmark: Compare performance of different cipher/KDF combos in MB/s and ms.
- GUI-based folder compression and encryption using `.tar.gz` wrapping.
- Multi-provider backend: OpenSSL, libsodium, and Argon2 are all supported and switchable at runtime.

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
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. Configure the project with CMake:
   ```bash
   cmake -S . -B build
   ```

3. Build the project:
   ```bash
   cmake --build build --config Release
   ```

4. Run the application:
   ```bash
   cd build
   ./OpenCryptUI
   ```

5. Run the tests:
   ```bash
   cd build
   ./OpenCryptUITest
   ```

## Detailed Installation Instructions

For detailed installation instructions, please refer to the following:

- [Linux](installation/linux.md)
- [Windows](installation/windows.md)
- [macOS](installation/osx.md)

## Usage

1. Launch the application:
   ```bash
   ./OpenCryptUI
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

OpenCryptUI aims to implement several additional features found in expert-level encryption tools and hardened security workflows:

- **Hidden volumes:** Create hidden encrypted volumes within existing volumes for plausible deniability.
- **Shamir Secret Sharing:** Optionally split the encryption key into multiple shares (e.g. 3-of-5) to improve redundancy and reduce risk.
- **Hardware token integration:** Support for YubiKey (HMAC challenge/response or PGP smartcard mode) during key derivation.
- **Double-layer encryption:** Encrypt file using symmetric key, then encrypt that key with user's PGP or RSA hardware key.
- **Plausible deniability modes:** Dual-password support to unlock either dummy or real data depending on the password entered.
- **Ephemeral unlock mode:** Temporary decryption with automatic cleanup after timeout or UI close.