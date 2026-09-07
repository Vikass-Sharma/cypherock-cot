#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <cassert>
#include <string>

#include <boost/asio.hpp>

#include "network/Framing.hpp"
#include "network/TcpServer.hpp"
#include "crypto/CryptoTests.hpp"
#include "ot/BaseOtTests.hpp"
#include "ot/CorrelatedOtTests.hpp"
#include "cot.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>

using namespace cot::network;

// Independent tests of the framing layer:
// 1. One complete frame
// 2. Multiple frames received together
// 3. Frame split across arbitrary chunk boundaries (including 1 byte at a time)
// 4. Rejection of invalid/excessive frame size
void run_framing_unit_tests() {
    std::cout << "[Framing Tests] Running independent TCP framing unit tests...\n";

    // Test 1: One complete frame
    {
        FrameParser parser;
        std::vector<uint8_t> dummy_payload = { 0xDE, 0xAD, 0xBE, 0xEF };
        auto frame = create_frame(dummy_payload.data(), dummy_payload.size());

        parser.feed(frame.data(), frame.size());
        assert(parser.has_frame());
        assert(parser.ready_count() == 1);
        auto extracted = parser.pop_frame();
        assert(extracted == dummy_payload);
        assert(!parser.has_frame());
        std::cout << "  - Test 1 (One complete frame in single chunk): PASSED\n";
    }

    // Test 2: Multiple frames received together in a single buffer
    {
        FrameParser parser;
        std::vector<uint8_t> p1 = { 0x01, 0x02 };
        std::vector<uint8_t> p2 = { 0xAA, 0xBB, 0xCC };
        std::vector<uint8_t> p3 = { 0x10, 0x20, 0x30, 0x40, 0x50 };

        auto f1 = create_frame(p1.data(), p1.size());
        auto f2 = create_frame(p2.data(), p2.size());
        auto f3 = create_frame(p3.data(), p3.size());

        std::vector<uint8_t> concatenated;
        concatenated.insert(concatenated.end(), f1.begin(), f1.end());
        concatenated.insert(concatenated.end(), f2.begin(), f2.end());
        concatenated.insert(concatenated.end(), f3.begin(), f3.end());

        parser.feed(concatenated.data(), concatenated.size());
        assert(parser.ready_count() == 3);
        assert(parser.pop_frame() == p1);
        assert(parser.pop_frame() == p2);
        assert(parser.pop_frame() == p3);
        assert(!parser.has_frame());
        std::cout << "  - Test 2 (Multiple frames in single chunk): PASSED\n";
    }

    // Test 3: Frame split across multiple TCP reads (extreme test: 1 byte at a time)
    {
        FrameParser parser;
        std::vector<uint8_t> p = { 0xCA, 0xFE, 0xBA, 0xBE, 0x42 };
        auto f = create_frame(p.data(), p.size());

        // Feed byte by byte
        for (size_t i = 0; i < f.size(); ++i) {
            assert(!parser.has_frame()); // should remain incomplete until the very last byte
            parser.feed(&f[i], 1);
        }
        assert(parser.has_frame());
        assert(parser.pop_frame() == p);
        assert(!parser.has_frame());
        std::cout << "  - Test 3 (Split frame fed 1 byte at a time): PASSED\n";
    }

    // Test 4: Rejection of excessive frame sizes
    {
        FrameParser parser;
        // Construct header claiming 100 KB payload (exceeds 64 KB MAX_FRAME_PAYLOAD_SIZE)
        uint8_t bad_header[4] = { 0x00, 0x01, 0x86, 0xA0 }; // 100,000 in big-endian
        bool exception_thrown = false;
        try {
            parser.feed(bad_header, 4);
        } catch (const std::runtime_error& e) {
            exception_thrown = true;
        }
        assert(exception_thrown);
        std::cout << "  - Test 4 (Excessive frame size rejection): PASSED\n";
    }

    std::cout << "[Framing Tests] All framing unit tests successfully PASSED!\n\n";
}

int main(int argc, char* argv[]) {
    bool test_only = false;
    uint16_t port = 9000;
    std::string host = "127.0.0.1";
    int case_num = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--test-only") {
            test_only = true;
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--case" && i + 1 < argc) {
            case_num = std::stoi(argv[++i]);
        } else if (arg.rfind("--", 0) != 0) {
            port = static_cast<uint16_t>(std::stoi(arg));
        }
    }

    if (test_only) {
        std::cout << "=========================================================\n";
        std::cout << " Cypherock COT Server - Unit Test Suite\n";
        std::cout << "=========================================================\n\n";

        run_framing_unit_tests();

        bool crypto_ok = cot::crypto::run_crypto_unit_tests();
        if (!crypto_ok) {
            std::cerr << "[Server Error] Cryptographic primitive tests failed!\n";
            return 1;
        }

        bool ot_ok = cot::ot::run_base_ot_unit_tests();
        if (!ot_ok) {
            std::cerr << "[Server Error] Base OT tests failed!\n";
            return 1;
        }

        bool cot_ok = cot::ot::run_correlated_ot_unit_tests();
        if (!cot_ok) {
            std::cerr << "[Server Error] Correlated OT tests failed!\n";
            return 1;
        }

        return 0;
    }

    try {
        boost::asio::io_context io_ctx;
        TcpServer server(io_ctx, host, port);

        // Run Stage 7 batched COT / MTA session
        bool success = server.run_cot_session(case_num);
        return success ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "[Server Error] " << e.what() << "\n";
        return 1;
    }
}
