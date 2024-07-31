# Building OpenCryptUI on Windows

## Prerequisites

1. **MSYS2**: Install MSYS2 from [msys2.org](https://www.msys2.org/).

2. **Install dependencies**: Open the MSYS2 terminal and run the following commands:
   ```sh
   pacman -Syu --noconfirm
   pacman -S --noconfirm \
     mingw-w64-x86_64-toolchain \
     mingw-w64-x86_64-cmake \
     mingw-w64-x86_64-ninja \
     mingw-w64-x86_64-openssl \
     mingw-w64-x86_64-libsodium \
     mingw-w64-x86_64-argon2 \
     mingw-w64-x86_64-qt5-base \
     mingw-w64-x86_64-qt5-tools \
     cmake \
     gcc \
     mingw-w64-x86_64-ntldd
   ```

## Build Steps

1. **Clone the repository**:
   ```sh
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. **Set environment variables and configure the build**:
   ```sh
   QT5_CONFIG=$(find /mingw64/ -name "Qt5Config.cmake" -o -name "qt5-config.cmake" | head -n 1)
   if [ -z "$QT5_CONFIG" ]; then
     echo "Qt5Config.cmake not found!"
     exit 1
   fi
   QT5_DIR=$(dirname ${QT5_CONFIG})
   echo "Qt5_DIR=${QT5_DIR}" >> $GITHUB_ENV
   echo "CMAKE_MODULE_PATH=${QT5_DIR}" >> $GITHUB_ENV

   echo "Setting up environment variables..."
   echo "OPENSSL_ROOT_DIR=/mingw64" >> $GITHUB_ENV
   echo "OPENSSL_INCLUDE_DIR=/mingw64/include" >> $GITHUB_ENV
   echo "OPENSSL_CRYPTO_LIBRARY=/mingw64/lib/libcrypto.a" >> $GITHUB_ENV
   echo "OPENSSL_SSL_LIBRARY=/mingw64/lib/libssl.a" >> $GITHUB_ENV
   echo "CMAKE_PREFIX_PATH=/mingw64" >> $GITHUB_ENV
   echo "ARGON2_LIB_DIR=/mingw64/lib" >> $GITHUB_ENV
   echo "ARGON2_INCLUDE_DIR=/mingw64/include" >> $GITHUB_ENV
   echo "SODIUM_LIB_DIR=/mingw64/lib" >> $GITHUB_ENV
   echo "SODIUM_INCLUDE_DIR=/mingw64/include" >> $GITHUB_ENV
   echo "/mingw64/bin" >> $GITHUB_PATH
   ```

3. **Build the project**:
   ```sh
   cmake -S . -B build -G "MinGW Makefiles" \
     -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR}" \
     -DOPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR}" \
     -DOPENSSL_CRYPTO_LIBRARY="${OPENSSL_CRYPTO_LIBRARY}" \
     -DOPENSSL_SSL_LIBRARY="${OPENSSL_SSL_LIBRARY}" \
     -DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}" \
     -DCMAKE_MODULE_PATH="${CMAKE_MODULE_PATH}" \
     -DQt5_DIR="${QT5_DIR}"

   cmake --build build --config Release
   ```

4. **Copy DLLs**:
   ```sh
   mkdir -p build/platforms
   mkdir -p build/styles

   NTLDD_PATH=$(find /mingw64/bin -name "ntldd.exe" | head -n 1)
   if [ -z "$NTLDD_PATH" ]; then
     echo "ntldd.exe not found!"
     exit 1
   fi

   DLL_PATHS=$(mktemp)
   "$NTLDD_PATH" -R build/EncryptionApp.exe | while IFS= read -r line
   do
     if [[ "$line" =~ [A-Za-z]:\\[^[:space:]]+\.dll ]]; then
       dll_path="${BASH_REMATCH[0]}"
       echo "$dll_path" >> "$DLL_PATHS"
     fi
   done

   cat "$DLL_PATHS" | while IFS= read -r dll_path
   do
     if [[ "$dll_path" != *Windows* ]]; then
       cp "$dll_path" build/
     fi
   done
   rm "$DLL_PATHS"

   cp /mingw64/bin/libglib-2.0-0.dll build/
   cp /mingw64/bin/libgraphite2.dll build/
   cp /mingw64/bin/libintl-8.dll build/
   cp /mingw64/share/qt5/plugins/platforms/qwindows.dll build/platforms/
   cp /mingw64/share/qt5/plugins/styles/qwindowsvistastyle.dll build/styles/
   ```
