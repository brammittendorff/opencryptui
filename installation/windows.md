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
     mingw-w64-x86_64-ntldd \
     git
   ```

## Build Steps

1. **Clone the repository**:
   ```sh
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. **Set environment variables and configure the build**:
   ```sh
   # Find Qt5 paths
   QT5_CONFIG=$(find /mingw64/ -name "Qt5Config.cmake" -o -name "qt5-config.cmake" | head -n 1)
   if [ -z "$QT5_CONFIG" ]; then
     echo "Qt5Config.cmake not found!"
     exit 1
   fi
   QT5_DIR=$(dirname ${QT5_CONFIG})
   
   # Set environment variables for the build
   export Qt5_DIR=${QT5_DIR}
   export CMAKE_MODULE_PATH=${QT5_DIR}
   export OPENSSL_ROOT_DIR=/mingw64
   export OPENSSL_INCLUDE_DIR=/mingw64/include
   export OPENSSL_CRYPTO_LIBRARY=/mingw64/lib/libcrypto.a
   export OPENSSL_SSL_LIBRARY=/mingw64/lib/libssl.a
   export CMAKE_PREFIX_PATH=/mingw64
   export ARGON2_LIB_DIR=/mingw64/lib
   export ARGON2_INCLUDE_DIR=/mingw64/include
   export SODIUM_LIB_DIR=/mingw64/lib
   export SODIUM_INCLUDE_DIR=/mingw64/include
   export PATH=$PATH:/mingw64/bin
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
   mkdir -p build/imageformats
   mkdir -p build/iconengines

   # Find ntldd.exe for dependency scanning
   NTLDD_PATH=$(find /mingw64/bin -name "ntldd.exe" | head -n 1)
   if [ -z "$NTLDD_PATH" ]; then
     echo "ntldd.exe not found!"
     exit 1
   fi

   # Scan for dependencies
   DLL_PATHS=$(mktemp)
   "$NTLDD_PATH" -R build/OpenCryptUI.exe | grep -i "mingw" | grep -v "not found" | awk '{print $3}' | sort -u > "$DLL_PATHS"

   # Copy dependencies
   while IFS= read -r dll_path; do
     if [[ -f "$dll_path" ]]; then
       cp "$dll_path" build/ || echo "Failed to copy $dll_path"
     fi
   done < "$DLL_PATHS"
   rm "$DLL_PATHS"

   # Copy essential Qt plugins
   cp /mingw64/share/qt5/plugins/platforms/qwindows.dll build/platforms/
   cp /mingw64/share/qt5/plugins/styles/qwindowsvistastyle.dll build/styles/
   cp /mingw64/share/qt5/plugins/imageformats/qjpeg.dll build/imageformats/
   cp /mingw64/share/qt5/plugins/imageformats/qgif.dll build/imageformats/
   cp /mingw64/share/qt5/plugins/imageformats/qsvg.dll build/imageformats/
   cp /mingw64/share/qt5/plugins/imageformats/qpng.dll build/imageformats/
   cp /mingw64/share/qt5/plugins/iconengines/qsvgicon.dll build/iconengines/
   ```

5. **Run the application**:
   ```sh
   cd build
   ./OpenCryptUI.exe
   ```

6. **Run the tests**:
   ```sh
   cd build
   ./OpenCryptUITest.exe
   ```

7. **Run tests with minimal logging (CI mode)**:
   ```sh
   cd build
   export CI=true
   export QT_LOGGING_RULES="*.debug=false;*.info=false;*.warning=false"
   export QT_MESSAGE_PATTERN=""
   ./OpenCryptUITest.exe -silent -v1
   ```
