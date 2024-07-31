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
   echo "ARGON2_LIB_DIR=$(brew --prefix argon2)/lib" >> $GITHUB_ENV
   echo "ARGON2_INCLUDE_DIR=$(brew --prefix argon2)/include" >> $GITHUB_ENV
   echo "SODIUM_LIB_DIR=$(brew --prefix libsodium)/lib" >> $GITHUB_ENV
   echo "SODIUM_INCLUDE_DIR=$(brew --prefix libsodium)/include" >> $GITHUB_ENV
   echo "Qt5_DIR=$(brew --prefix qt@5)/lib/cmake/Qt5" >> $GITHUB_ENV
   echo "CMAKE_PREFIX_PATH=$(brew --prefix qt@5)" >> $GITHUB_ENV
   ```

3. **Build the project**:
   ```sh
   cmake -S . -B build -G Ninja
   cmake --build build --config Release
   ```
