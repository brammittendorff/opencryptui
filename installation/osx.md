# Building OpenCryptUI on macOS

## Prerequisites

### 1. Install Homebrew

Homebrew is a package manager for macOS that simplifies the installation of software.

Open a terminal and run the following command to install Homebrew:
```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install Development Tools

Use Homebrew to install the necessary development tools:

```sh
brew install cmake git
```

### 3. Install Qt

Use Homebrew to install Qt:

```sh
brew install qt@5
```

### 4. Install OpenSSL

Use Homebrew to install OpenSSL:

```sh
brew install openssl
```

### 5. Install Libsodium

Use Homebrew to install Libsodium:

```sh
brew install libsodium
```

### 6. Install Argon2

Use Homebrew to install Argon2:

```sh
brew install argon2
```

## Building the Project

1. **Clone the Repository**:

   Open a terminal and clone the repository:
   ```sh
   git clone <repository_url>
   cd opencryptui
   ```

2. **Create a Build Directory**:
   ```sh
   mkdir build
   cd build
   ```

3. **Run CMake**:

   Ensure the Qt and OpenSSL paths are correctly set. You may need to specify the path for OpenSSL because it is keg-only in Homebrew:

   ```sh
   cmake -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@1.1) -DQt5_DIR=$(brew --prefix qt@5)/lib/cmake/Qt5 ..
   ```

4. **Build the Project**:
   Use `make` to build the project:
   ```sh
   make
   ```

5. **Run the Application**:
   Navigate to the build directory and run the application:
   ```sh
   ./EncryptionApp
   ```
