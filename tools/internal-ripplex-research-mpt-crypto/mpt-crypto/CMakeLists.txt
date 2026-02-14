cmake_minimum_required(VERSION 3.10)
project(mpt-crypto C CXX)

# Set C++ standard for utility tool
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find Dependencies ---
find_package(OpenSSL REQUIRED)

# --- Add libsecp256k1 from source ---
set(SECP256K1_SOURCE_DIR /Users/mcenk/Documents/Projects/ripplex-research/secp256k1 CACHE PATH "Path to secp256k1 source directory")
if(NOT EXISTS ${SECP256K1_SOURCE_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "Could not find libsecp256k1 source directory at ${SECP256K1_SOURCE_DIR}.")
endif()

# Configure libsecp256k1 build options
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)

# Add libsecp256k1 as a sub-project
add_subdirectory(${SECP256K1_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/secp256k1_build)

# --- Define The Library ---
# Build as STATIC library for easier distribution
add_library(mpt-crypto STATIC
        src/elgamal.c
        src/equality_proof.c
        src/proof_same_plaintext.c
        src/proof_same_plaintext_multi.c
        src/bulletproof.c
        src/proof_link.c
        src/proof_link.c
        src/proof_pok_sk.c
        src/commitments.c

        # --- LIBSECP256K1 INTERNAL C FILES (Essential for Scalar Math) ---

        # ${SECP256K1_SOURCE_DIR}/src/field.c
        # ${SECP256K1_SOURCE_DIR}/src/group.c
        )

# --- Set Include Directories ---
# We only need the public include directories now
target_include_directories(mpt-crypto
        PUBLIC include                       # Your public API
        PRIVATE ${SECP256K1_SOURCE_DIR}/include # libsecp256k1's public 'include' dir
        PRIVATE ${SECP256K1_SOURCE_DIR}/src     # <-- ADDED for internal headers (scalar.h, field.h, etc.)
        )

# --- Link Dependencies ---
target_link_libraries(mpt-crypto
        PUBLIC secp256k1       # Link against the public libsecp256k1 target
        PUBLIC OpenSSL::Crypto
        )

# --- Testing ---
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# --- Utility Tool ---
option(BUILD_UTILITY "Build confidential utility tool" ON)
if(BUILD_UTILITY)
    add_executable(confidential_utility tools/confidential_utility.cpp)
    target_include_directories(confidential_utility PUBLIC include)
    target_link_libraries(confidential_utility PUBLIC mpt-crypto)
endif()