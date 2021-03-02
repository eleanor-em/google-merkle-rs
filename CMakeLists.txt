cmake_minimum_required(VERSION 3.17)
project(google_merkle)

set(CMAKE_CXX_STANDARD 20)
set(CXXFLAGS -g)

set(OPENSSL_ROOT_DIR /usr/lib/libressl)
find_package(OpenSSL REQUIRED)
include_directories(.)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB MERKLE_SRC
        "merkletree/*.h"
        "merkletree/*.cc"
        )

add_library(merkletree ${MERKLE_SRC} c/merkletree.cpp c/verifier.cpp)

add_executable(google_merkle ${MERKLE_SRC} main.cpp)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
