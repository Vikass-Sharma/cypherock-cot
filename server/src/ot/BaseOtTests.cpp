#include "ot/BaseOtTests.hpp"
#include "ot/BaseOt.hpp"
#include "crypto/TrezorCrypto.hpp"

#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <vector>

namespace cot::ot {

bool run_base_ot_unit_tests() {
    std::cout << "=========================================================\n";
    std::cout << " Stage 5: Base Oblivious Transfer (COT.pdf Appendix A.3.1)\n";
    std::cout << "=========================================================\n\n";

    bool all_passed = true;

    auto check_test = [&](const std::string& name, bool condition, const std::string& info = "") {
        std::cout << "  - [" << (condition ? "PASS" : "FAIL") << "] " << name;
        if (!info.empty()) {
            std::cout << " -> " << info;
        }
        std::cout << "\n";
        if (!condition) all_passed = false;
    };

    // Deterministic test setup
    uint8_t det_a[32] = {0}; det_a[31] = 7;
    uint8_t m0[32]; std::memset(m0, 0x11, 32);
    uint8_t m1[32]; std::memset(m1, 0x22, 32);

    // -----------------------------------------------------------------------
    // Test 1: Deterministic Base OT with choice c = 0
    // -----------------------------------------------------------------------
    std::cout << "--- Deterministic Base OT Test: choice c = 0 ---\n";
    {
        uint8_t det_b0[32] = {0}; det_b0[31] = 11;
        uint8_t choice = 0;

        BaseOtAlice alice;
        bool alice_ok = alice.init(det_a);
        check_test("Alice init (a=7)", alice_ok,
                   "A=" + crypto::to_hex(alice.get_A(), 33));

        BaseOtBob bob;
        uint8_t B[33] = {0};
        bool bob_ok = bob.receive_A_and_compute_B(alice.get_A(), choice, B, det_b0);
        check_test("Bob receive A & compute B (b=11, c=0)", bob_ok,
                   "B=" + crypto::to_hex(B, 33));

        bool alice_rx_b = alice.receive_B(B);
        check_test("Alice receive B & derive keys", alice_rx_b,
                   "k0=" + crypto::to_hex(alice.get_k0(), 32) +
                   ", k1=" + crypto::to_hex(alice.get_k1(), 32));

        // Critical algebra checks:
        // When c = 0: k0 must match kc, and k1 must not match kc
        bool k0_match = (std::memcmp(alice.get_k0(), bob.get_kc(), 32) == 0);
        bool k1_mismatch = (std::memcmp(alice.get_k1(), bob.get_kc(), 32) != 0);
        check_test("Algebra check: k0 == kc (c=0)", k0_match,
                   "kc=" + crypto::to_hex(bob.get_kc(), 32));
        check_test("Algebra check: k1 != kc (c=0)", k1_mismatch);

        // Round 3: Alice encrypts m0 and m1
        uint8_t e0[32] = {0}, e1[32] = {0};
        bool enc_ok = alice.encrypt_messages(m0, m1, e0, e1);
        check_test("Alice encrypt messages (m0, m1)", enc_ok,
                   "e0=" + crypto::to_hex(e0, 32) +
                   ", e1=" + crypto::to_hex(e1, 32));

        // Bob decrypts selected ciphertext e0 with kc
        uint8_t mc[32] = {0};
        bool dec_ok = bob.decrypt_selected(e0, e1, mc);
        bool msg_match = (std::memcmp(mc, m0, 32) == 0);
        check_test("Bob decrypt selected: mc == m0 (c=0)", dec_ok && msg_match,
                   "Recovered: " + crypto::to_hex(mc, 32));

        // Wrong-key decryption check: attempt to decrypt e1 using key kc (which is k0 != k1)
        uint8_t wrong_dec[32] = {0};
        decrypt_ot_message(e1, bob.get_kc(), 1, wrong_dec);
        bool wrong_key_fails = (std::memcmp(wrong_dec, m1, 32) != 0);
        check_test("Security check: unused ciphertext e1 cannot be decrypted with kc", wrong_key_fails);
    }
    std::cout << "\n";

    // -----------------------------------------------------------------------
    // Test 2: Deterministic Base OT with choice c = 1
    // -----------------------------------------------------------------------
    std::cout << "--- Deterministic Base OT Test: choice c = 1 ---\n";
    {
        uint8_t det_b1[32] = {0}; det_b1[31] = 13;
        uint8_t choice = 1;

        BaseOtAlice alice;
        bool alice_ok = alice.init(det_a);
        check_test("Alice init (a=7)", alice_ok,
                   "A=" + crypto::to_hex(alice.get_A(), 33));

        BaseOtBob bob;
        uint8_t B[33] = {0};
        bool bob_ok = bob.receive_A_and_compute_B(alice.get_A(), choice, B, det_b1);
        check_test("Bob receive A & compute B (b=13, c=1)", bob_ok,
                   "B=" + crypto::to_hex(B, 33));

        bool alice_rx_b = alice.receive_B(B);
        check_test("Alice receive B & derive keys", alice_rx_b,
                   "k0=" + crypto::to_hex(alice.get_k0(), 32) +
                   ", k1=" + crypto::to_hex(alice.get_k1(), 32));

        // Critical algebra checks:
        // When c = 1: k1 must match kc, and k0 must not match kc
        bool k1_match = (std::memcmp(alice.get_k1(), bob.get_kc(), 32) == 0);
        bool k0_mismatch = (std::memcmp(alice.get_k0(), bob.get_kc(), 32) != 0);
        check_test("Algebra check: k1 == kc (c=1)", k1_match,
                   "kc=" + crypto::to_hex(bob.get_kc(), 32));
        check_test("Algebra check: k0 != kc (c=1)", k0_mismatch);

        // Round 3: Alice encrypts m0 and m1
        uint8_t e0[32] = {0}, e1[32] = {0};
        bool enc_ok = alice.encrypt_messages(m0, m1, e0, e1);
        check_test("Alice encrypt messages (m0, m1)", enc_ok,
                   "e0=" + crypto::to_hex(e0, 32) +
                   ", e1=" + crypto::to_hex(e1, 32));

        // Bob decrypts selected ciphertext e1 with kc
        uint8_t mc[32] = {0};
        bool dec_ok = bob.decrypt_selected(e0, e1, mc);
        bool msg_match = (std::memcmp(mc, m1, 32) == 0);
        check_test("Bob decrypt selected: mc == m1 (c=1)", dec_ok && msg_match,
                   "Recovered: " + crypto::to_hex(mc, 32));

        // Wrong-key decryption check: attempt to decrypt e0 using key kc (which is k1 != k0)
        uint8_t wrong_dec[32] = {0};
        decrypt_ot_message(e0, bob.get_kc(), 0, wrong_dec);
        bool wrong_key_fails = (std::memcmp(wrong_dec, m0, 32) != 0);
        check_test("Security check: unused ciphertext e0 cannot be decrypted with kc", wrong_key_fails);
    }
    std::cout << "\n";

    // -----------------------------------------------------------------------
    // Test 3: Multiple Random In-Memory Protocol Iterations
    // -----------------------------------------------------------------------
    std::cout << "--- Random In-Memory Protocol Executions (5 runs) ---\n";
    {
        bool all_random_ok = true;
        for (int run = 1; run <= 5; ++run) {
            uint8_t rand_m0[32], rand_m1[32];
            crypto::generate_random_32(rand_m0);
            crypto::generate_random_32(rand_m1);

            uint8_t rand_buf[32];
            crypto::generate_random_32(rand_buf);
            uint8_t choice_bit = rand_buf[0] & 1;

            BaseOtAlice alice;
            alice.init();

            BaseOtBob bob;
            uint8_t B[33];
            bob.receive_A_and_compute_B(alice.get_A(), choice_bit, B);

            alice.receive_B(B);

            uint8_t e0[32], e1[32];
            alice.encrypt_messages(rand_m0, rand_m1, e0, e1);

            uint8_t mc[32];
            bool dec_ok = bob.decrypt_selected(e0, e1, mc);

            const uint8_t* expected_m = (choice_bit == 0) ? rand_m0 : rand_m1;
            if (!dec_ok || std::memcmp(mc, expected_m, 32) != 0) {
                all_random_ok = false;
            }
        }
        check_test("5 independent random Base OT protocol runs", all_random_ok, "All 5 recovered mc successfully");
    }
    std::cout << "\n";

    // -----------------------------------------------------------------------
    // Test 4: Negative & Boundary Tests
    // -----------------------------------------------------------------------
    std::cout << "--- Base OT Negative / Boundary Tests ---\n";
    {
        BaseOtBob bob;
        uint8_t valid_A[33];
        BaseOtAlice alice;
        alice.init();
        std::memcpy(valid_A, alice.get_A(), 33);

        uint8_t dummy_B[33];

        // 1. Invalid choice bit (choice = 2)
        bool rej_choice_2 = !bob.receive_A_and_compute_B(valid_A, 2, dummy_B);
        check_test("Reject invalid choice bit c = 2", rej_choice_2);

        // 2. Invalid choice bit (choice = 255)
        bool rej_choice_255 = !bob.receive_A_and_compute_B(valid_A, 255, dummy_B);
        check_test("Reject invalid choice bit c = 255", rej_choice_255);

        // 3. Malformed point A (bad prefix 0x01)
        uint8_t bad_A[33];
        std::memcpy(bad_A, valid_A, 33);
        bad_A[0] = 0x01;
        bool rej_bad_A = !bob.receive_A_and_compute_B(bad_A, 0, dummy_B);
        check_test("Reject malformed point A with bad prefix 0x01", rej_bad_A);

        // 4. Malformed point B passed to Alice
        uint8_t bad_B[33] = {0};
        bad_B[0] = 0x02;
        bad_B[32] = 0x05; // Non-quadratic residue, not on curve
        bool rej_bad_B = !alice.receive_B(bad_B);
        check_test("Reject malformed point B not on curve", rej_bad_B);

        // 5. Invalid scalar for Alice init (scalar = 0)
        uint8_t zero_scalar[32] = {0};
        BaseOtAlice bad_alice;
        bool rej_zero_scalar = !bad_alice.init(zero_scalar);
        check_test("Reject scalar == 0 for Alice init", rej_zero_scalar);

        // 6. Invalid scalar for Alice init (scalar = n)
        bool rej_n_scalar = !bad_alice.init(crypto::SECP256K1_CURVE_ORDER_BE.data());
        check_test("Reject scalar == n for Alice init", rej_n_scalar);
    }

    std::cout << "\n=========================================================\n";
    std::cout << " Stage 5 C++ Base OT Test Result: " << (all_passed ? "ALL PASSED" : "FAILED") << "\n";
    std::cout << "=========================================================\n\n";

    return all_passed;
}

} // namespace cot::ot
