#include "crypto/CryptoTests.hpp"
#include "crypto/TrezorCrypto.hpp"

#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <vector>

namespace cot::crypto {

bool run_crypto_unit_tests() {
    std::cout << "=========================================================\n";
    std::cout << " Stage 4: Cryptographic Primitives Validation (Server/C++)\n";
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

    // A. Secure Random 32-byte Values
    {
        uint8_t r1[32] = {0};
        uint8_t r2[32] = {0};
        generate_random_32(r1);
        generate_random_32(r2);

        bool r1_nonzero = false;
        bool different = false;
        for (size_t i = 0; i < 32; ++i) {
            if (r1[i] != 0) r1_nonzero = true;
            if (r1[i] != r2[i]) different = true;
        }
        check_test("A. Random 32-byte Generation", r1_nonzero && different,
                   "Len: 32, Entropy: arc4random_buf via Trezor random_buffer hook");
    }

    // B. SHA-256
    {
        // NIST Vector 1: ""
        uint8_t d1[32];
        sha256(nullptr, 0, d1);
        std::string h1 = to_hex(d1, 32);
        check_test("B. SHA-256 (Empty string)", 
                   h1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   h1);

        // NIST Vector 2: "abc"
        const uint8_t abc[] = {'a', 'b', 'c'};
        uint8_t d2[32];
        sha256(abc, 3, d2);
        std::string h2 = to_hex(d2, 32);
        check_test("B. SHA-256 ('abc')", 
                   h2 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                   h2);
    }

    // C. secp256k1 generator multiplication
    uint8_t pub_g[33] = {0};
    uint8_t pub_2g[33] = {0};
    uint8_t pub_3g[33] = {0};
    {
        // Scalar 1 -> G
        uint8_t priv1[32] = {0};
        priv1[31] = 1;
        bool ok1 = scalar_multiply_base(priv1, pub_g);
        std::string h_g = to_hex(pub_g, 33);
        check_test("C. Generator mult (priv=1 -> G)",
                   ok1 && h_g == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                   h_g);

        // Scalar 2 -> 2G
        uint8_t priv2[32] = {0};
        priv2[31] = 2;
        bool ok2 = scalar_multiply_base(priv2, pub_2g);
        std::string h_2g = to_hex(pub_2g, 33);
        check_test("C. Generator mult (priv=2 -> 2G)",
                   ok2 && h_2g == "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                   h_2g);

        // Scalar 3 -> 3G
        uint8_t priv3[32] = {0};
        priv3[31] = 3;
        bool ok3 = scalar_multiply_base(priv3, pub_3g);
        std::string h_3g = to_hex(pub_3g, 33);
        check_test("C. Generator mult (priv=3 -> 3G)",
                   ok3 && h_3g == "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                   h_3g);
    }

    // D. ECDH shared-secret calculation (Alice priv = 2, Bob priv = 3 -> 6G)
    {
        uint8_t priv_alice[32] = {0}; priv_alice[31] = 2;
        uint8_t priv_bob[32] = {0};   priv_bob[31] = 3;

        uint8_t secret_alice[32] = {0};
        uint8_t secret_bob[32] = {0};

        bool ok_a = ecdh(priv_alice, pub_3g, secret_alice);
        bool ok_b = ecdh(priv_bob, pub_2g, secret_bob);

        std::string h_sa = to_hex(secret_alice, 32);
        std::string h_sb = to_hex(secret_bob, 32);
        bool match = (ok_a && ok_b && h_sa == h_sb &&
                      h_sa == "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556");
        check_test("D. ECDH shared secret (2 * 3G == 3 * 2G == X(6G))",
                   match,
                   "Normalized 32-byte X: " + h_sa);
    }

    // E. EC point encoding
    {
        bool valid_g = is_valid_point(pub_g);
        bool valid_2g = is_valid_point(pub_2g);
        bool prefix_ok = (pub_g[0] == 0x02 || pub_g[0] == 0x03);
        check_test("E. EC point encoding (33 bytes SEC1 compressed)",
                   valid_g && valid_2g && prefix_ok,
                   "Prefix: 0x0" + std::to_string(pub_g[0]) + ", len: 33");
    }

    // F. EC point addition (2G + 3G = 5G)
    {
        uint8_t sum_point[33] = {0};
        bool ok_add = point_add(pub_2g, pub_3g, sum_point);
        std::string h_sum = to_hex(sum_point, 33);

        // Expected 5G from scalar mult
        uint8_t priv5[32] = {0}; priv5[31] = 5;
        uint8_t pub_5g[33] = {0};
        scalar_multiply_base(priv5, pub_5g);
        std::string h_5g = to_hex(pub_5g, 33);

        bool match_5g = (ok_add && h_sum == h_5g &&
                         h_sum == "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4");
        check_test("F. Point addition (2G + 3G == 5G)",
                   match_5g,
                   h_sum);
    }

    // G. Modular arithmetic modulo p
    {
        // Field prime p in 32 bytes
        const auto& p_bytes = SECP256K1_FIELD_PRIME_BE;

        // p - 1
        uint8_t p_minus_1[32];
        std::memcpy(p_minus_1, p_bytes.data(), 32);
        p_minus_1[31] = 0x2E; // 0x2F - 1 = 0x2E

        // Scalar 2
        uint8_t two[32] = {0};
        two[31] = 2;

        // 1. Add: (p - 1) + 2 mod p == 1
        uint8_t add_res[32] = {0};
        field_add(p_minus_1, two, add_res);
        std::string h_add = to_hex(add_res, 32);
        check_test("G. Field Add ((p - 1) + 2 mod p == 1)",
                   h_add == "0000000000000000000000000000000000000000000000000000000000000001",
                   h_add);

        // 2. Sub: 1 - 2 mod p == p - 1
        uint8_t one[32] = {0};
        one[31] = 1;
        uint8_t sub_res[32] = {0};
        field_sub(one, two, sub_res);
        std::string h_sub = to_hex(sub_res, 32);
        std::string h_p_minus_1 = to_hex(p_minus_1, 32);
        check_test("G. Field Sub (1 - 2 mod p == p - 1)",
                   h_sub == h_p_minus_1,
                   h_sub);

        // 3. Mul: (p - 1) * (p - 1) mod p == (-1)*(-1) == 1
        uint8_t mul_res[32] = {0};
        field_mul(p_minus_1, p_minus_1, mul_res);
        std::string h_mul = to_hex(mul_res, 32);
        check_test("G. Field Mul ((p - 1) * (p - 1) mod p == 1)",
                   h_mul == "0000000000000000000000000000000000000000000000000000000000000001",
                   h_mul);
    }

    // H. Negative / Boundary tests
    {
        // 1. Scalar = 0 rejected
        uint8_t zero_scalar[32] = {0};
        uint8_t dummy_out[33];
        bool rej_zero = !scalar_multiply_base(zero_scalar, dummy_out) && !is_valid_scalar(zero_scalar);
        check_test("H. Reject scalar == 0", rej_zero);

        // 2. Scalar = n rejected (order of curve)
        const auto& n_bytes = SECP256K1_CURVE_ORDER_BE;
        bool rej_n = !scalar_multiply_base(n_bytes.data(), dummy_out) && !is_valid_scalar(n_bytes.data());
        check_test("H. Reject scalar == n", rej_n);

        // 3. Scalar = p - 1 rejected as scalar (since p - 1 > n), but valid in field
        uint8_t p_minus_1[32];
        std::memcpy(p_minus_1, SECP256K1_FIELD_PRIME_BE.data(), 32);
        p_minus_1[31] = 0x2E;
        bool rej_p_minus_1 = !scalar_multiply_base(p_minus_1, dummy_out) && !is_valid_scalar(p_minus_1);
        check_test("H. Reject scalar == p - 1 (since p - 1 > n)", rej_p_minus_1);

        // 4. Malformed point prefix: 0x01
        uint8_t bad_prefix_pt[33];
        std::memcpy(bad_prefix_pt, pub_g, 33);
        bad_prefix_pt[0] = 0x01;
        bool rej_prefix = !is_valid_point(bad_prefix_pt);
        check_test("H. Reject point with invalid prefix 0x01", rej_prefix);

        // 5. Point not on curve: X = 5 has no square root mod p (non-quadratic residue)
        uint8_t non_curve_pt[33] = {0};
        non_curve_pt[0] = 0x02;
        non_curve_pt[32] = 0x05;
        bool rej_non_curve = !is_valid_point(non_curve_pt);
        check_test("H. Reject point not on curve (X=5 is non-quadratic residue)", rej_non_curve);
    }

    std::cout << "\n=========================================================\n";
    std::cout << " Stage 4 C++ Test Result: " << (all_passed ? "ALL PASSED" : "FAILED") << "\n";
    std::cout << "=========================================================\n\n";

    return all_passed;
}

} // namespace cot::crypto
