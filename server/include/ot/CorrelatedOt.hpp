#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

namespace cot::ot {

// Canonical field element validation: checks if val < secp256k1 field prime p
bool is_canonical_field_element(const uint8_t val[32]);

// Extracts bit i from 32-byte big-endian value y, where bit 0 is the least-significant bit (LSB)
uint8_t get_le_bit(const uint8_t y[32], size_t bit_idx);

// Calculates powers of 2 modulo p: out = 2^i mod p
void get_power_of_two_mod_p(size_t i, uint8_t out[32]);

// Alice (Server) for Correlated OT (COT.pdf Appendix A.3.2 and A.3.3)
class CorrelatedOtAlice {
public:
    CorrelatedOtAlice();

    // Initialize Alice with multiplicative term x in F_p.
    // If deterministic is true, U_i are derived deterministically for reproducible cross-language vectors.
    // If deterministic is false, U_i are sampled using CSPRNG.
    bool init(const uint8_t x[32], bool deterministic = false);

    // Accessors for bit i (0 <= i < 256)
    const uint8_t* get_m0(size_t i) const;
    const uint8_t* get_m1(size_t i) const;
    const uint8_t* get_Ui(size_t i) const;

    // Computes additive share U = -sum(i=0..255) 2^i * U_i mod p
    bool compute_share_U(uint8_t U_out[32]) const;

    const uint8_t* get_x() const { return x_.data(); }

private:
    std::array<uint8_t, 32> x_;
    std::array<std::array<uint8_t, 32>, 256> Ui_;
    std::array<std::array<uint8_t, 32>, 256> m0_;
    std::array<std::array<uint8_t, 32>, 256> m1_;
    bool initialized_ = false;
};

// Bob (Client) for Correlated OT (COT.pdf Appendix A.3.2 and A.3.3)
class CorrelatedOtBob {
public:
    CorrelatedOtBob();

    // Initialize Bob with multiplicative term y in F_p.
    bool init(const uint8_t y[32]);

    // Gets choice bit for index i: c_i = y_i (0 <= i < 256)
    uint8_t get_choice_bit(size_t i) const;

    // Bob records the decrypted selected message mc_i from the i-th Base OT
    bool record_mc(size_t i, const uint8_t mc[32]);

    // Computes additive share V = sum(i=0..255) 2^i * mc_i mod p
    bool compute_share_V(uint8_t V_out[32]) const;

    const uint8_t* get_mc(size_t i) const;
    const uint8_t* get_y() const { return y_.data(); }

private:
    std::array<uint8_t, 32> y_;
    std::array<std::array<uint8_t, 32>, 256> mc_;
    std::array<bool, 256> mc_recorded_{};
    bool initialized_ = false;
};

// Result structure for COT / MTA execution
struct CorrelatedOtResult {
    bool success = false;
    size_t base_ot_count = 0;
    size_t successful_mc_count = 0;
    size_t correlation_check_count = 0;
    std::array<uint8_t, 32> U{};
    std::array<uint8_t, 32> V{};
    std::array<uint8_t, 32> expected_xy{};
    std::array<uint8_t, 32> actual_sum{};
    bool invariant_passed = false;
    std::string error_message;
};

// In-memory protocol harness executing 256 Base OTs between Alice and Bob
CorrelatedOtResult execute_correlated_ot(CorrelatedOtAlice& alice, CorrelatedOtBob& bob, bool deterministic_ot = false);

} // namespace cot::ot
