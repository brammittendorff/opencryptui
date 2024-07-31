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
