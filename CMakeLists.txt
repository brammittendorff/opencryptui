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

# OpenSSL configuration
if(WIN32)
    # Comment out the OpenSSL find_package for Windows
    # find_package(OpenSSL REQUIRED)

    # Set OpenSSL paths for Windows
    set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
    set(OPENSSL_LIBRARIES "C:/Program Files/OpenSSL-Win64/lib/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/libcrypto.lib")
else()
    # For non-Windows platforms, use find_package
    find_package(OpenSSL REQUIRED)
endif()

# Find Argon2 and Sodium (Scrypt) packages
find_package(PkgConfig REQUIRED)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_search_module(ARGON2 REQUIRED libargon2)
    pkg_search_module(SODIUM REQUIRED libsodium)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(ARGON2_LIB_DIR $ENV{ARGON2_LIB_DIR})
    set(ARGON2_INCLUDE_DIR $ENV{ARGON2_INCLUDE_DIR})
    set(SODIUM_LIB_DIR $ENV{SODIUM_LIB_DIR})
    set(SODIUM_INCLUDE_DIR $ENV{SODIUM_INCLUDE_DIR})
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(ARGON2_LIB_DIR $ENV{ARGON2_LIB_DIR})
    set(ARGON2_INCLUDE_DIR $ENV{ARGON2_INCLUDE_DIR})
    set(SODIUM_LIB_DIR $ENV{SODIUM_LIB_DIR})
    set(SODIUM_INCLUDE_DIR $ENV{SODIUM_INCLUDE_DIR})
endif()

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

target_include_directories(EncryptionApp PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${ARGON2_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_directories(EncryptionApp PRIVATE 
    ${ARGON2_LIB_DIR}
    ${SODIUM_LIB_DIR}
)

target_link_libraries(EncryptionApp PUBLIC 
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    ${OPENSSL_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
    argon2
    sodium
)

# Print paths for debugging
message(STATUS "Qt5_DIR: ${Qt5_DIR}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "ARGON2_INCLUDE_DIRS: ${ARGON2_INCLUDE_DIRS}")
message(STATUS "SODIUM_INCLUDE_DIRS: ${SODIUM_INCLUDE_DIRS}")
message(STATUS "ARGON2_LIB_DIR: ${ARGON2_LIB_DIR}")
message(STATUS "SODIUM_LIB_DIR: ${SODIUM_LIB_DIR}")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")