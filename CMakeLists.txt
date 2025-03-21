cmake_minimum_required(VERSION 3.5)
project(drcom-cpp-client)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

find_package(yaml-cpp REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})

add_executable(drcom-cpp-client
    main.cpp
    config.cpp
    utils.cpp
)

target_link_libraries(drcom-cpp-client
    OpenSSL::SSL
    OpenSSL::Crypto
    yaml-cpp
    pthread
)
