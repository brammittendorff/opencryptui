# Building OpenCryptUI on Linux

## Prerequisites

### 1. Install Development Tools

Open a terminal and run the following commands to install the necessary development tools:

#### On Debian-based systems (e.g., Ubuntu):
```sh
sudo apt update
sudo apt install build-essential cmake git
```

#### On Red Hat-based systems (e.g., Fedora):
```sh
sudo dnf groupinstall "Development Tools"
sudo dnf install cmake git
```

### 2. Install Qt

#### On Debian-based systems:
```sh
sudo apt install qt5-default qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
```

#### On Red Hat-based systems:
```sh
sudo dnf install qt5-qtbase-devel
```

### 3. Install OpenSSL

#### On Debian-based systems:
```sh
sudo apt install libssl-dev
```

#### On Red Hat-based systems:
```sh
sudo dnf install openssl-devel
```

### 4. Install Libsodium

#### On Debian-based systems:
```sh
sudo apt install libsodium-dev
```

#### On Red Hat-based systems:
```sh
sudo dnf install libsodium-devel
```

### 5. Install Argon2

Argon2 is often included in the default repositories:

#### On Debian-based systems:
```sh
sudo apt install libargon2-dev
```

#### On Red Hat-based systems:
```sh
sudo dnf install libargon2-devel
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
   Generate the build files:
   ```sh
   cmake ..
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