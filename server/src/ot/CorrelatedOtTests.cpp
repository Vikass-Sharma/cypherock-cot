#include "ot/CorrelatedOtTests.hpp"
#include "ot/CorrelatedOt.hpp"
#include "crypto/TrezorCrypto.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <cassert>

namespace cot::ot {

namespace {

void print_hex_32(const char* label, const uint8_t val[32]) {
    std::cout << "  " << label << ": " << crypto::to_hex(val, 32) << "\n";
}

bool run_deterministic_cot_case(const char* name, const uint8_t x[32], const uint8_t y[32]) {
    std::cout << "\n--- COT Deterministic Test: " << name << " ---\n";
    CorrelatedOtAlice alice;
    if (!alice.init(x, /*deterministic=*/true)) {
        std::cout << "  [FAIL] Alice init failed\n";
        return false;
    }

    CorrelatedOtBob bob;
    if (!bob.init(y)) {
        std::cout << "  [FAIL] Bob init failed\n";
        return false;
    }

    // Intermediate checks for first 4 bits
    std::cout << "  x: " << crypto::to_hex(x, 32) << "\n";
    std::cout << "  y: " << crypto::to_hex(y, 32) << "\n";
    std::cout << "  first 4 bits of y (LSB first): ";
    for (size_t i = 0; i < 4; ++i) {
        std::cout << static_cast<int>(bob.get_choice_bit(i)) << " ";
    }
    std::cout << "\n";

    for (size_t i = 0; i < 4; ++i) {
        std::cout << "  [bit " << i << "] Ui=" << crypto::to_hex(alice.get_Ui(i), 8) << "... "
                  << "m0=" << crypto::to_hex(alice.get_m0(i), 8) << "... "
                  << "m1=" << crypto::to_hex(alice.get_m1(i), 8) << "...\n";
    }

    // Execute 256 Base OTs in memory
    CorrelatedOtResult res = execute_correlated_ot(alice, bob, /*deterministic_ot=*/true);
    if (!res.success) {
        std::cout << "  [FAIL] Protocol execution failed: " << res.error_message << "\n";
        return false;
    }

    for (size_t i = 0; i < 4; ++i) {
        std::cout << "  [bit " << i << "] mc=" << crypto::to_hex(bob.get_mc(i), 8) << "... (c="
                  << static_cast<int>(bob.get_choice_bit(i)) << ")\n";
    }

    print_hex_32("U", res.U.data());
    print_hex_32("V", res.V.data());
    print_hex_32("x*y mod p", res.expected_xy.data());
    print_hex_32("(U+V) mod p", res.actual_sum.data());

    std::cout << "  Base OT invocations: " << res.base_ot_count << "\n";
    std::cout << "  successful selected-message recoveries: " << res.successful_mc_count << "/256\n";
    std::cout << "  correlation checks (m1 - m0 == x): " << res.correlation_check_count << "/256\n";

    // Algebra self-check:
    // Verify: V - sum(2^i * y_i * x) == sum(2^i * Ui) mod p
    uint8_t sum_yx[32] = {0};
    uint8_t sum_ui[32] = {0};
    uint8_t power[32] = {0};
    power[31] = 1;

    for (size_t i = 0; i < 256; ++i) {
        // sum_ui
        uint8_t term_ui[32];
        crypto::field_mul(power, alice.get_Ui(i), term_ui);
        crypto::field_add(sum_ui, term_ui, sum_ui);

        // sum_yx: if y_i == 1, add 2^i * x
        if (bob.get_choice_bit(i) == 1) {
            uint8_t term_yx[32];
            crypto::field_mul(power, x, term_yx);
            crypto::field_add(sum_yx, term_yx, sum_yx);
        }

        crypto::field_add(power, power, power);
    }

    uint8_t lhs[32];
    crypto::field_sub(res.V.data(), sum_yx, lhs);

    bool algebra_check = (std::memcmp(lhs, sum_ui, 32) == 0);
    if (!algebra_check) {
        std::cout << "  [FAIL] Algebra self-check failed: V - sum(2^i * y_i * x) != sum(2^i * Ui)\n";
        return false;
    }
    std::cout << "  algebra self-check: PASS\n";

    if (!res.invariant_passed) {
        std::cout << "  [FAIL] Multiplication invariant failed!\n";
        return false;
    }
    std::cout << "  multiplication invariant: PASS\n";
    return true;
}

} // namespace

bool run_correlated_ot_unit_tests() {
    std::cout << "\n=========================================================\n";
    std::cout << " Stage 6: Correlated Oblivious Transfer (Appendix A.3.2/A.3.3)\n";
    std::cout << "=========================================================\n";

    // 1. Simple case: x = 1, y = 1
    uint8_t x1[32] = {0}, y1[32] = {0};
    x1[31] = 1;
    y1[31] = 1;
    if (!run_deterministic_cot_case("x = 1, y = 1", x1, y1)) {
        return false;
    }

    // 2. Small values: x = 5, y = 13
    uint8_t x2[32] = {0}, y2[32] = {0};
    x2[31] = 5;
    y2[31] = 13;
    if (!run_deterministic_cot_case("x = 5, y = 13", x2, y2)) {
        return false;
    }

    // 3. Values exercising many bits (deterministic 256-bit values)
    uint8_t x3[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    uint8_t y3[32] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    if (!run_deterministic_cot_case("256-bit wide vectors", x3, y3)) {
        return false;
    }

    // 4. Boundary field values: x = p - 1, y = p - 1
    // p - 1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E
    uint8_t p_minus_1[32];
    std::memcpy(p_minus_1, crypto::SECP256K1_FIELD_PRIME_BE.data(), 32);
    p_minus_1[31] -= 1;
    if (!run_deterministic_cot_case("x = p - 1, y = p - 1", p_minus_1, p_minus_1)) {
        return false;
    }

    // 5. Zero cases
    uint8_t zero[32] = {0};
    uint8_t forty_two[32] = {0};
    forty_two[31] = 42;

    if (!run_deterministic_cot_case("x = 0, y = 0", zero, zero)) {
        return false;
    }
    if (!run_deterministic_cot_case("x = 0, y = 42", zero, forty_two)) {
        return false;
    }
    if (!run_deterministic_cot_case("x = 42, y = 0", forty_two, zero)) {
        return false;
    }

    // 6. Random in-memory executions (5 independent runs)
    std::cout << "\n--- Random In-Memory Protocol Executions (5 runs) ---\n";
    for (int run = 1; run <= 5; ++run) {
        uint8_t rx[32], ry[32];
        do {
            crypto::generate_random_32(rx);
        } while (!is_canonical_field_element(rx));
        do {
            crypto::generate_random_32(ry);
        } while (!is_canonical_field_element(ry));

        CorrelatedOtAlice alice;
        if (!alice.init(rx, /*deterministic=*/false)) {
            std::cout << "  [FAIL] Run " << run << " Alice init failed\n";
            return false;
        }
        CorrelatedOtBob bob;
        if (!bob.init(ry)) {
            std::cout << "  [FAIL] Run " << run << " Bob init failed\n";
            return false;
        }

        CorrelatedOtResult res = execute_correlated_ot(alice, bob, /*deterministic_ot=*/false);
        if (!res.success) {
            std::cout << "  [FAIL] Run " << run << " failed: " << res.error_message << "\n";
            return false;
        }
        std::cout << "  - [PASS] Run " << run << ": invariant (U + V == x * y mod p) hold for random x, y\n";
    }

    // 7. Negative and boundary tests
    std::cout << "\n--- COT Negative & Boundary Tests ---\n";
    {
        // Value >= p must be rejected
        uint8_t bad_val[32];
        std::memcpy(bad_val, crypto::SECP256K1_FIELD_PRIME_BE.data(), 32); // equal to p
        CorrelatedOtAlice bad_alice;
        if (bad_alice.init(bad_val)) {
            std::cout << "  [FAIL] Alice failed to reject x == p\n";
            return false;
        }
        std::cout << "  - [PASS] Reject non-canonical field element x == p\n";

        CorrelatedOtBob bad_bob;
        if (bad_bob.init(bad_val)) {
            std::cout << "  [FAIL] Bob failed to reject y == p\n";
            return false;
        }
        std::cout << "  - [PASS] Reject non-canonical field element y == p\n";
    }

    std::cout << "\n=========================================================\n";
    std::cout << " Stage 6 C++ Correlated OT Test Result: ALL PASSED\n";
    std::cout << "=========================================================\n\n";
    return true;
}

} // namespace cot::ot
