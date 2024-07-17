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
    src/mainwindow.h
    src/encryptionengine.cpp
    src/encryptionengine.h
    src/encryptionworker.cpp
    src/encryptionworker.h
    src/customlistwidget.cpp    # Add this line
    src/customlistwidget.h      # Add this line
    ui/mainwindow.ui
)

add_executable(EncryptionApp ${PROJECT_SOURCES})

target_link_libraries(EncryptionApp PRIVATE 
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
)

target_include_directories(EncryptionApp PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src    # Change this to src to include customlistwidget.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${ARGON2_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)
