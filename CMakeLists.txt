cmake_minimum_required(VERSION 3.14)
project(EncryptionApp LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt packages
find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Find Argon2 and Sodium (Scrypt) packages
find_package(PkgConfig REQUIRED)
pkg_search_module(ARGON2 REQUIRED libargon2)
pkg_search_module(SODIUM REQUIRED libsodium)

# Add this line to set the UI file directory
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui)

set(PROJECT_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    include/mainwindow.h
    src/encryptionengine_init.cpp
    src/encryptionengine_fileops.cpp
    src/encryptionengine_keyderivation.cpp
    src/encryptionengine_crypto.cpp
    src/encryptionengine_benchmark.cpp
    include/encryptionengine.h
    src/encryptionworker.cpp
    include/encryptionworker.h
    src/customlistwidget.cpp
    include/customlistwidget.h
    ui/mainwindow.ui
)

add_executable(EncryptionApp ${PROJECT_SOURCES})

target_link_libraries(EncryptionApp PUBLIC 
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
)

target_include_directories(EncryptionApp PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include    # Include directory for header files
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${ARGON2_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

# Print paths for debugging
message(STATUS "Qt5_DIR: ${Qt5_DIR}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OpenSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OpenSSL_LIBRARIES}")
message(STATUS "ARGON2_INCLUDE_DIRS: ${ARGON2_INCLUDE_DIRS}")
message(STATUS "SODIUM_INCLUDE_DIRS: ${SODIUM_INCLUDE_DIRS}")
