add_executable(cot_server
    src/main.cpp
    src/crypto_platform.c
    src/crypto/TrezorCrypto.cpp
    src/crypto/CryptoTests.cpp
    src/ot/BaseOt.cpp
    src/ot/BaseOtTests.cpp
    src/ot/CorrelatedOt.cpp
    src/ot/CorrelatedOtTests.cpp
    src/network/Framing.cpp
    src/network/TcpServer.cpp
)

target_include_directories(cot_server PRIVATE
    include
)

target_link_libraries(cot_server PRIVATE
    Boost::headers
    trezor_crypto
    cot_proto_c
    nanopb::protobuf-nanopb-static
)
