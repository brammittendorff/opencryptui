# Building OpenCryptUI on macOS

## Prerequisites

1. **Homebrew**: Install Homebrew from [brew.sh](https://brew.sh/).

2. **Install dependencies**: Open the terminal and run the following commands:
   ```sh
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || { echo "Homebrew installation failed"; exit 1; }
   brew install qt@5 openssl libsodium argon2 ninja
   brew link --force qt@5
   ```

## Build Steps

1. **Clone the repository**:
   ```sh
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. **Set environment variables**:
   ```sh
   export ARGON2_LIB_DIR=$(brew --prefix argon2)/lib
   export ARGON2_INCLUDE_DIR=$(brew --prefix argon2)/include
   export SODIUM_LIB_DIR=$(brew --prefix libsodium)/lib
   export SODIUM_INCLUDE_DIR=$(brew --prefix libsodium)/include
   export Qt5_DIR=$(brew --prefix qt@5)/lib/cmake/Qt5
   export CMAKE_PREFIX_PATH=$(brew --prefix qt@5)
   export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
   export OPENSSL_INCLUDE_DIR=$(brew --prefix openssl)/include
   export OPENSSL_LIBRARIES=$(brew --prefix openssl)/lib
   ```

3. **Build the project**:
   ```sh
   cmake -S . -B build -G Ninja
   cmake --build build --config Release
   ```

4. **Run the application**:
   ```sh
   cd build
   ./OpenCryptUI
   ```

5. **Run the tests**:
   ```sh
   cd build
   ./OpenCryptUITest
   ```

6. **Run tests with minimal logging (CI mode)**:
   ```sh
   cd build
   env CI=true QT_LOGGING_RULES="*.debug=false;*.info=false;*.warning=false" QT_MESSAGE_PATTERN="" ./OpenCryptUITest -silent -v1
   ```
