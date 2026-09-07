cmake_minimum_required(VERSION 3.20)
project(cypherock_cot C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

# Boost (Asio) - modern Config mode (resolves CMP0167)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost REQUIRED CONFIG)

# Nanopb
find_package(nanopb REQUIRED)

# Audited Trezor Crypto Subtree (vendored directly)
set(TREZOR_CRYPTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/trezor-crypto")

# Define trezor_crypto library
set(TREZOR_CRYPTO_SRCS
    ${TREZOR_CRYPTO_DIR}/bignum.c
    ${TREZOR_CRYPTO_DIR}/ecdsa.c
    ${TREZOR_CRYPTO_DIR}/secp256k1.c
    ${TREZOR_CRYPTO_DIR}/curves.c
    ${TREZOR_CRYPTO_DIR}/memzero.c
    ${TREZOR_CRYPTO_DIR}/sha2.c
    ${TREZOR_CRYPTO_DIR}/rand.c
    ${TREZOR_CRYPTO_DIR}/hasher.c
    ${TREZOR_CRYPTO_DIR}/ripemd160.c
    ${TREZOR_CRYPTO_DIR}/sha3.c
    ${TREZOR_CRYPTO_DIR}/blake256.c
    ${TREZOR_CRYPTO_DIR}/blake2b.c
    ${TREZOR_CRYPTO_DIR}/groestl.c
    ${TREZOR_CRYPTO_DIR}/address.c
    ${TREZOR_CRYPTO_DIR}/base58.c
    ${TREZOR_CRYPTO_DIR}/hmac.c
    ${TREZOR_CRYPTO_DIR}/rfc6979.c
    ${TREZOR_CRYPTO_DIR}/hmac_drbg.c
    ${TREZOR_CRYPTO_DIR}/consteq.c
    ${TREZOR_CRYPTO_DIR}/fault_handler_noop.c
)

add_library(trezor_crypto STATIC ${TREZOR_CRYPTO_SRCS})

target_include_directories(trezor_crypto PUBLIC
    ${TREZOR_CRYPTO_DIR}
)

target_compile_definitions(trezor_crypto PUBLIC
    USE_KECCAK=1
    USE_ETHEREUM=0
    USE_MONERO=0
    USE_CARDANO=0
    USE_PRECOMPUTED_CP=0
)

# Nanopb code generation for cot.proto
set(PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(GEN_PROTO_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated_proto")
file(MAKE_DIRECTORY ${GEN_PROTO_DIR})

find_program(NANOPB_GENERATOR NAMES nanopb_generator nanopb_generator.py HINTS /opt/homebrew/bin REQUIRED)
set(PROTO_FILE "${PROTO_DIR}/cot.proto")
set(OPTIONS_FILE "${PROTO_DIR}/cot.options")
set(GEN_PB_SRC "${GEN_PROTO_DIR}/cot.pb.c")
set(GEN_PB_HDR "${GEN_PROTO_DIR}/cot.pb.h")

add_custom_command(
    OUTPUT ${GEN_PB_SRC} ${GEN_PB_HDR}
    COMMAND ${NANOPB_GENERATOR} -I ${PROTO_DIR} -D ${GEN_PROTO_DIR} ${PROTO_FILE}
    DEPENDS ${PROTO_FILE} ${OPTIONS_FILE}
    COMMENT "Generating Nanopb C code from cot.proto"
)

add_library(cot_proto_c STATIC ${GEN_PB_SRC} ${GEN_PB_HDR})
target_link_libraries(cot_proto_c PUBLIC nanopb::protobuf-nanopb-static)
target_include_directories(cot_proto_c PUBLIC ${GEN_PROTO_DIR})

add_subdirectory(server)
