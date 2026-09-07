#include "ot/CorrelatedOt.hpp"
#include "ot/BaseOt.hpp"
#include "crypto/TrezorCrypto.hpp"

#include <cstring>
#include <stdexcept>
#include <iostream>

namespace cot::ot {

namespace {

void write_be_u32(uint32_t val, uint8_t out[4]) {
    out[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(val & 0xFF);
}

void derive_deterministic_scalar(const char* prefix, uint32_t index, uint8_t out[32]) {
    uint32_t nonce = 0;
    size_t prefix_len = std::strlen(prefix);
    std::vector<uint8_t> buf(prefix_len + 8);
    std::memcpy(buf.data(), prefix, prefix_len);
    write_be_u32(index, buf.data() + prefix_len);

    while (true) {
        write_be_u32(nonce, buf.data() + prefix_len + 4);
        crypto::sha256(buf.data(), buf.size(), out);
        if (crypto::is_valid_scalar(out)) {
            return;
        }
        nonce++;
    }
}

void derive_deterministic_field_element(const char* prefix, uint32_t index, uint8_t out[32]) {
    size_t prefix_len = std::strlen(prefix);
    std::vector<uint8_t> buf(prefix_len + 4);
    std::memcpy(buf.data(), prefix, prefix_len);
    write_be_u32(index, buf.data() + prefix_len);

    uint8_t hash[32];
    crypto::sha256(buf.data(), buf.size(), hash);
    const uint8_t zero[32] = {0};
    crypto::field_add(hash, zero, out);
}

} // namespace

bool is_canonical_field_element(const uint8_t val[32]) {
    // Value must be strictly less than secp256k1 field prime p
    return std::memcmp(val, crypto::SECP256K1_FIELD_PRIME_BE.data(), 32) < 0;
}

uint8_t get_le_bit(const uint8_t y[32], size_t bit_idx) {
    if (bit_idx >= 256) return 0;
    size_t byte_idx = 31 - (bit_idx / 8);
    uint8_t bit_in_byte = static_cast<uint8_t>(bit_idx % 8);
    return static_cast<uint8_t>((y[byte_idx] >> bit_in_byte) & 1);
}

void get_power_of_two_mod_p(size_t i, uint8_t out[32]) {
    std::memset(out, 0, 32);
    out[31] = 1; // 2^0 = 1
    for (size_t step = 0; step < i; ++step) {
        crypto::field_add(out, out, out);
    }
}

// ---------------------------------------------------------------------------
// CorrelatedOtAlice
// ---------------------------------------------------------------------------
CorrelatedOtAlice::CorrelatedOtAlice() {
    x_.fill(0);
    for (size_t i = 0; i < 256; ++i) {
        Ui_[i].fill(0);
        m0_[i].fill(0);
        m1_[i].fill(0);
    }
}

bool CorrelatedOtAlice::init(const uint8_t x[32], bool deterministic) {
    if (!is_canonical_field_element(x)) {
        return false;
    }
    std::memcpy(x_.data(), x, 32);

    for (size_t i = 0; i < 256; ++i) {
        if (deterministic) {
            derive_deterministic_field_element("COT_TEST_U_", static_cast<uint32_t>(i), Ui_[i].data());
        } else {
            uint8_t rand_buf[32];
            do {
                crypto::generate_random_32(rand_buf);
            } while (!is_canonical_field_element(rand_buf));
            std::memcpy(Ui_[i].data(), rand_buf, 32);
        }

        // m0_i = Ui
        std::memcpy(m0_[i].data(), Ui_[i].data(), 32);

        // m1_i = (Ui + x) mod p
        crypto::field_add(Ui_[i].data(), x_.data(), m1_[i].data());
    }

    initialized_ = true;
    return true;
}

const uint8_t* CorrelatedOtAlice::get_m0(size_t i) const {
    if (i >= 256 || !initialized_) return nullptr;
    return m0_[i].data();
}

const uint8_t* CorrelatedOtAlice::get_m1(size_t i) const {
    if (i >= 256 || !initialized_) return nullptr;
    return m1_[i].data();
}

const uint8_t* CorrelatedOtAlice::get_Ui(size_t i) const {
    if (i >= 256 || !initialized_) return nullptr;
    return Ui_[i].data();
}

bool CorrelatedOtAlice::compute_share_U(uint8_t U_out[32]) const {
    if (!initialized_) return false;

    // S = sum(i=0..255) 2^i * Ui mod p
    uint8_t sum[32] = {0};
    uint8_t power[32] = {0};
    power[31] = 1; // 2^0 = 1

    for (size_t i = 0; i < 256; ++i) {
        uint8_t term[32] = {0};
        crypto::field_mul(power, Ui_[i].data(), term);
        crypto::field_add(sum, term, sum);

        // power = (power * 2) mod p = (power + power) mod p
        crypto::field_add(power, power, power);
    }

    // U = -S mod p = (0 - S) mod p
    const uint8_t zero[32] = {0};
    crypto::field_sub(zero, sum, U_out);
    return true;
}

// ---------------------------------------------------------------------------
// CorrelatedOtBob
// ---------------------------------------------------------------------------
CorrelatedOtBob::CorrelatedOtBob() {
    y_.fill(0);
    for (size_t i = 0; i < 256; ++i) {
        mc_[i].fill(0);
    }
    mc_recorded_.fill(false);
}

bool CorrelatedOtBob::init(const uint8_t y[32]) {
    if (!is_canonical_field_element(y)) {
        return false;
    }
    std::memcpy(y_.data(), y, 32);
    mc_recorded_.fill(false);
    initialized_ = true;
    return true;
}

uint8_t CorrelatedOtBob::get_choice_bit(size_t i) const {
    if (i >= 256 || !initialized_) return 0;
    return get_le_bit(y_.data(), i);
}

bool CorrelatedOtBob::record_mc(size_t i, const uint8_t mc[32]) {
    if (i >= 256 || !initialized_) return false;
    std::memcpy(mc_[i].data(), mc, 32);
    mc_recorded_[i] = true;
    return true;
}

const uint8_t* CorrelatedOtBob::get_mc(size_t i) const {
    if (i >= 256 || !initialized_ || !mc_recorded_[i]) return nullptr;
    return mc_[i].data();
}

bool CorrelatedOtBob::compute_share_V(uint8_t V_out[32]) const {
    if (!initialized_) return false;
    for (size_t i = 0; i < 256; ++i) {
        if (!mc_recorded_[i]) return false;
    }

    // V = sum(i=0..255) 2^i * mc_i mod p
    uint8_t sum[32] = {0};
    uint8_t power[32] = {0};
    power[31] = 1; // 2^0 = 1

    for (size_t i = 0; i < 256; ++i) {
        uint8_t term[32] = {0};
        crypto::field_mul(power, mc_[i].data(), term);
        crypto::field_add(sum, term, sum);

        crypto::field_add(power, power, power);
    }

    std::memcpy(V_out, sum, 32);
    return true;
}

// ---------------------------------------------------------------------------
// execute_correlated_ot
// ---------------------------------------------------------------------------
CorrelatedOtResult execute_correlated_ot(CorrelatedOtAlice& alice, CorrelatedOtBob& bob, bool deterministic_ot) {
    CorrelatedOtResult result;
    result.base_ot_count = 0;
    result.successful_mc_count = 0;
    result.correlation_check_count = 0;

    for (size_t i = 0; i < 256; ++i) {
        BaseOtAlice base_alice;
        BaseOtBob base_bob;

        uint8_t det_a[32], det_b[32];
        if (deterministic_ot) {
            derive_deterministic_scalar("COT_TEST_A_", static_cast<uint32_t>(i), det_a);
            derive_deterministic_scalar("COT_TEST_B_", static_cast<uint32_t>(i), det_b);
        }

        // Alice Round 1: A = aG
        if (!base_alice.init(deterministic_ot ? det_a : nullptr)) {
            result.error_message = "Alice Base OT init failed at index " + std::to_string(i);
            return result;
        }
        const uint8_t* A = base_alice.get_A();

        // Bob Round 2: Receives A, choice c_i = y_i, computes B, derives kc
        uint8_t choice = bob.get_choice_bit(i);
        uint8_t B[33];
        if (!base_bob.receive_A_and_compute_B(A, choice, B, deterministic_ot ? det_b : nullptr)) {
            result.error_message = "Bob Base OT compute failed at index " + std::to_string(i);
            return result;
        }

        // Alice Round 2: Receives B, derives k0 and k1
        if (!base_alice.receive_B(B)) {
            result.error_message = "Alice Base OT receive B failed at index " + std::to_string(i);
            return result;
        }

        // Alice Round 3: Encrypts m0 and m1
        const uint8_t* m0 = alice.get_m0(i);
        const uint8_t* m1 = alice.get_m1(i);
        uint8_t e0[32], e1[32];
        if (!base_alice.encrypt_messages(m0, m1, e0, e1)) {
            result.error_message = "Alice Base OT encryption failed at index " + std::to_string(i);
            return result;
        }

        // Bob Round 3: Decrypts selected ciphertext
        uint8_t mc[32];
        if (!base_bob.decrypt_selected(e0, e1, mc)) {
            result.error_message = "Bob Base OT decryption failed at index " + std::to_string(i);
            return result;
        }

        // Bob records mc
        if (!bob.record_mc(i, mc)) {
            result.error_message = "Bob failed to record mc at index " + std::to_string(i);
            return result;
        }

        result.base_ot_count++;

        // Verify Bob got expected selected message: mc == (choice ? m1 : m0)
        const uint8_t* expected_mc = (choice == 0) ? m0 : m1;
        if (std::memcmp(mc, expected_mc, 32) == 0) {
            result.successful_mc_count++;
        }

        // Verify correlation: (m1 - m0) mod p == x mod p
        uint8_t diff[32];
        crypto::field_sub(m1, m0, diff);
        if (std::memcmp(diff, alice.get_x(), 32) == 0) {
            result.correlation_check_count++;
        }
    }

    if (!alice.compute_share_U(result.U.data())) {
        result.error_message = "Alice failed to compute share U";
        return result;
    }

    if (!bob.compute_share_V(result.V.data())) {
        result.error_message = "Bob failed to compute share V";
        return result;
    }

    // Compute expected x * y mod p
    crypto::field_mul(alice.get_x(), bob.get_y(), result.expected_xy.data());

    // Compute actual (U + V) mod p
    crypto::field_add(result.U.data(), result.V.data(), result.actual_sum.data());

    // Check invariant: (U + V) mod p == (x * y) mod p
    result.invariant_passed = (std::memcmp(result.expected_xy.data(), result.actual_sum.data(), 32) == 0);
    result.success = result.invariant_passed && (result.successful_mc_count == 256) && (result.correlation_check_count == 256);

    return result;
}

} // namespace cot::ot
