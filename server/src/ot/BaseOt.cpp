#include "ot/BaseOt.hpp"
#include "crypto/TrezorCrypto.hpp"

#include <cstring>
#include <stdexcept>

extern "C" {
#include "memzero.h"
}

namespace cot::ot {

void derive_ot_mask(const uint8_t key[32], uint32_t index, uint8_t mask_out[32]) {
    // 36 bytes: key (32 bytes) || uint32_be(index) (4 bytes)
    uint8_t buffer[36];
    std::memcpy(buffer, key, 32);
    buffer[32] = static_cast<uint8_t>((index >> 24) & 0xFF);
    buffer[33] = static_cast<uint8_t>((index >> 16) & 0xFF);
    buffer[34] = static_cast<uint8_t>((index >> 8) & 0xFF);
    buffer[35] = static_cast<uint8_t>(index & 0xFF);

    uint8_t raw_hash[32];
    crypto::sha256(buffer, sizeof(buffer), raw_hash);

    // Reduce raw SHA256 digest modulo p
    uint8_t zero[32] = {0};
    crypto::field_add(raw_hash, zero, mask_out);

    memzero(buffer, sizeof(buffer));
    memzero(raw_hash, sizeof(raw_hash));
}

void encrypt_ot_message(const uint8_t m[32], const uint8_t key[32], uint32_t index, uint8_t e_out[32]) {
    uint8_t mask[32];
    derive_ot_mask(key, index, mask);
    crypto::field_add(m, mask, e_out);
    memzero(mask, sizeof(mask));
}

void decrypt_ot_message(const uint8_t e[32], const uint8_t key[32], uint32_t index, uint8_t m_out[32]) {
    uint8_t mask[32];
    derive_ot_mask(key, index, mask);
    crypto::field_sub(e, mask, m_out);
    memzero(mask, sizeof(mask));
}

// ---------------------------------------------------------------------------
// BaseOtAlice Implementation
// ---------------------------------------------------------------------------

BaseOtAlice::BaseOtAlice() {
    a_.fill(0);
    A_.fill(0);
    B_.fill(0);
    B_minus_A_.fill(0);
    k0_.fill(0);
    k1_.fill(0);
}

bool BaseOtAlice::init(const uint8_t* deterministic_a) {
    if (deterministic_a != nullptr) {
        if (!crypto::is_valid_scalar(deterministic_a)) {
            return false;
        }
        std::memcpy(a_.data(), deterministic_a, 32);
    } else {
        do {
            crypto::generate_random_32(a_.data());
        } while (!crypto::is_valid_scalar(a_.data()));
    }

    if (!crypto::scalar_multiply_base(a_.data(), A_.data())) {
        return false;
    }

    initialized_ = true;
    keys_derived_ = false;
    return true;
}

bool BaseOtAlice::receive_B(const uint8_t B[33]) {
    if (!initialized_) {
        return false;
    }
    if (!crypto::is_valid_point(B)) {
        return false;
    }
    std::memcpy(B_.data(), B, 33);

    // 1. k0 = (a * B)_x
    if (!crypto::ecdh(a_.data(), B_.data(), k0_.data())) {
        return false;
    }

    // 2. Compute -A: invert prefix parity (0x02 <-> 0x03)
    std::array<uint8_t, 33> neg_A = A_;
    neg_A[0] = (A_[0] == 0x02) ? 0x03 : 0x02;

    // 3. Compute B - A = B + (-A)
    if (!crypto::point_add(B_.data(), neg_A.data(), B_minus_A_.data())) {
        return false;
    }

    // 4. k1 = (a * (B - A))_x
    if (!crypto::ecdh(a_.data(), B_minus_A_.data(), k1_.data())) {
        return false;
    }

    keys_derived_ = true;
    return true;
}

bool BaseOtAlice::encrypt_messages(const uint8_t m0[32], const uint8_t m1[32],
                                   uint8_t e0_out[32], uint8_t e1_out[32]) {
    if (!keys_derived_) {
        return false;
    }
    encrypt_ot_message(m0, k0_.data(), 0, e0_out);
    encrypt_ot_message(m1, k1_.data(), 1, e1_out);
    return true;
}

// ---------------------------------------------------------------------------
// BaseOtBob Implementation
// ---------------------------------------------------------------------------

BaseOtBob::BaseOtBob() {
    b_.fill(0);
    A_.fill(0);
    B_.fill(0);
    kc_.fill(0);
}

bool BaseOtBob::receive_A_and_compute_B(const uint8_t A[33], uint8_t choice_bit,
                                       uint8_t B_out[33], const uint8_t* deterministic_b) {
    if (!crypto::is_valid_point(A)) {
        return false;
    }
    if (choice_bit != 0 && choice_bit != 1) {
        return false;
    }

    std::memcpy(A_.data(), A, 33);
    choice_ = choice_bit;

    if (deterministic_b != nullptr) {
        if (!crypto::is_valid_scalar(deterministic_b)) {
            return false;
        }
        std::memcpy(b_.data(), deterministic_b, 32);
    } else {
        do {
            crypto::generate_random_32(b_.data());
        } while (!crypto::is_valid_scalar(b_.data()));
    }

    // b*G
    std::array<uint8_t, 33> bG;
    if (!crypto::scalar_multiply_base(b_.data(), bG.data())) {
        return false;
    }

    if (choice_ == 0) {
        // B = bG
        B_ = bG;
    } else {
        // B = bG + A
        if (!crypto::point_add(bG.data(), A_.data(), B_.data())) {
            return false;
        }
    }

    std::memcpy(B_out, B_.data(), 33);

    // kc = (b * A)_x
    if (!crypto::ecdh(b_.data(), A_.data(), kc_.data())) {
        return false;
    }

    computed_ = true;
    return true;
}

bool BaseOtBob::decrypt_selected(const uint8_t e0[32], const uint8_t e1[32], uint8_t mc_out[32]) {
    if (!computed_) {
        return false;
    }
    const uint8_t* ec = (choice_ == 0) ? e0 : e1;
    decrypt_ot_message(ec, kc_.data(), choice_, mc_out);
    return true;
}

} // namespace cot::ot
