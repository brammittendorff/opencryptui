# Linux Build Instructions

## Prerequisites

1. **Install dependencies**: Open the terminal and run the following commands:
   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential cmake ninja-build git qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libssl-dev libsodium-dev libargon2-dev
   ```

## Build Steps

1. **Clone the repository**:
   ```sh
   git clone https://github.com/brammittendorff/opencryptui.git
   cd opencryptui
   ```

2. **Build the project**:
   ```sh
   cmake -S . -B build -G Ninja
   cmake --build build --config Release
   ```

3. **Run the application**:
   ```sh
   cd build
   ./OpenCryptUI
   ```

4. **Run the tests**:
   ```sh
   cd build
   ./OpenCryptUITest
   ```

5. **Run tests with minimal logging (CI mode)**:
   ```sh
   cd build
   env CI=true QT_LOGGING_RULES="*.debug=false;*.info=false;*.warning=false" QT_MESSAGE_PATTERN="" ./OpenCryptUITest -silent -v1
   ```
