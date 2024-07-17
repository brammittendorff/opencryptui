# Building OpenCryptUI on Windows

## Prerequisites

### 1. Install MinGW
1. **Download MinGW**:
   - Go to the [MinGW-w64](https://sourceforge.net/projects/mingw-w64/) page.
   - Download the latest version suitable for your system (usually `mingw-w64-install.exe`).

2. **Install MinGW**:
   - Run the installer and follow the prompts.
   - Choose the architecture (x86_64 for 64-bit systems).
   - Choose the version of the GCC compiler (the latest stable version is recommended).
   - Choose the threads model (win32 is usually fine).
   - Choose the exception model (dwarf for 32-bit, seh for 64-bit).
   - Install to a directory (e.g., `C:\mingw-w64`).

3. **Add MinGW to PATH**:
   - Go to Control Panel -> System and Security -> System -> Advanced system settings -> Environment Variables.
   - Under System variables, find the PATH variable, and click Edit.
   - Add the path to the MinGW `bin` directory (e.g., `C:\mingw-w64\bin`).

### 2. Install CMake
1. **Download CMake**:
   - Go to the [CMake Downloads](https://cmake.org/download/) page.
   - Download the installer for Windows (`cmake-X.Y.Z-windows-x86_64.msi`).

2. **Install CMake**:
   - Run the installer and follow the prompts.
   - Make sure to select the option to add CMake to the system PATH for all users.

### 3. Install Qt
1. **Download Qt**:
   - Go to the [Qt Downloads](https://www.qt.io/download) page.
   - Download the Qt Online Installer.

2. **Install Qt**:
   - Run the installer and follow the prompts.
   - Select the MinGW toolchain during installation.

### 4. Install OpenSSL
1. **Download OpenSSL**:
   - Go to [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html).
   - Download the full installer for OpenSSL.

2. **Install OpenSSL**:
   - Run the installer and follow the prompts.
   - Note the installation directory (e.g., `C:\OpenSSL-Win64`).

3. **Add OpenSSL to PATH**:
   - Add the path to the OpenSSL `bin` directory to your system PATH (e.g., `C:\OpenSSL-Win64\bin`).

### 5. Install Libsodium
1. **Download Libsodium**:
   - Go to the [Libsodium Releases](https://github.com/jedisct1/libsodium/releases) page.
   - Download the precompiled binaries for Windows.

2. **Install Libsodium**:
   - Extract the downloaded archive to a suitable location (e.g., `C:\libsodium`).

3. **Add Libsodium to PATH**:
   - Add the path to the Libsodium `bin` directory to your system PATH (e.g., `C:\libsodium\bin`).

### 6. Install Argon2

1. **Download and Build Argon2**:
   - Clone the Argon2 repository:
     ```sh
     git clone https://github.com/P-H-C/phc-winner-argon2.git
     cd phc-winner-argon2
     ```

2. **Build Argon2**:
   - Create a build directory and navigate to it:
     ```sh
     mkdir build
     cd build
     ```
   - Run CMake to configure the build:
     ```sh
     cmake -G "MinGW Makefiles" ..
     ```
   - Build Argon2 using `mingw32-make`:
     ```sh
     mingw32-make
     ```
   - Copy the `libargon2.a` file to a suitable directory (e.g., `C:\argon2\lib`) and the `argon2.h` header file to `C:\argon2\include`.

3. **Add Argon2 to PATH**:
   - Add the path to the Argon2 `bin` directory (if any) to your system PATH (e.g., `C:\argon2\bin`).

## Building the Project

1. **Clone the Repository**:

   Open Command Prompt or Git Bash and clone the repository:
   ```sh
   git clone <repository_url>
   cd opencryptui
   ```

2. Create a Build Directory

   ```sh
   mkdir build
   cd build
   ```

3. **Run CMake with MinGW**:
   Generate the build files for MinGW:
   ```sh
   cmake -G "MinGW Makefiles" ..
   ```

4. **Build the Project**:
   Use `mingw32-make` to build the project:
   ```sh
   mingw32-make
   ```

5. **Run the Application**:
   Navigate to the build directory and run the application:
   ```sh
   .\EncryptionApp.exe
   ```
