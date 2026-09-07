#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

namespace cot::ot {

// Concrete encryption/masking instantiation used for the mock implementation;
// the COT.pdf specifies the use of the OT-derived keys but does not prescribe
// this exact masking construction.
void derive_ot_mask(const uint8_t key[32], uint32_t index, uint8_t mask_out[32]);
void encrypt_ot_message(const uint8_t m[32], const uint8_t key[32], uint32_t index, uint8_t e_out[32]);
void decrypt_ot_message(const uint8_t e[32], const uint8_t key[32], uint32_t index, uint8_t m_out[32]);

// Alice (Server) for Base OT (COT.pdf Appendix A.3.1)
class BaseOtAlice {
public:
    BaseOtAlice();

    // Round 1: Generate ephemeral scalar a in [1, n-1] and compute public point A = a*G (33 bytes)
    // If deterministic_a is provided, uses it after validation; otherwise generates via CSPRNG.
    bool init(const uint8_t* deterministic_a = nullptr);

    // Round 2: Receive public point B from Bob, compute k0 = (aB)_x and k1 = (a(B-A))_x
    bool receive_B(const uint8_t B[33]);

    // Round 3: Encrypt m0 with k0 and m1 with k1, producing ciphertexts e0 and e1
    bool encrypt_messages(const uint8_t m0[32], const uint8_t m1[32], uint8_t e0_out[32], uint8_t e1_out[32]);

    // Accessors for protocol inspection and cross-language verification
    const uint8_t* get_a() const { return a_.data(); }
    const uint8_t* get_A() const { return A_.data(); }
    const uint8_t* get_k0() const { return k0_.data(); }
    const uint8_t* get_k1() const { return k1_.data(); }
    const uint8_t* get_B_minus_A() const { return B_minus_A_.data(); }

private:
    std::array<uint8_t, 32> a_;
    std::array<uint8_t, 33> A_;
    std::array<uint8_t, 33> B_;
    std::array<uint8_t, 33> B_minus_A_;
    std::array<uint8_t, 32> k0_;
    std::array<uint8_t, 32> k1_;
    bool initialized_ = false;
    bool keys_derived_ = false;
};

// Bob (Client) for Base OT (COT.pdf Appendix A.3.1)
class BaseOtBob {
public:
    BaseOtBob();

    // Round 2: Receive A, validate, generate ephemeral b in [1, n-1], compute B = bG (if c=0) or B = bG + A (if c=1),
    // and derive decryption key kc = (bA)_x
    bool receive_A_and_compute_B(const uint8_t A[33], uint8_t choice_bit,
                                 uint8_t B_out[33], const uint8_t* deterministic_b = nullptr);

    // Round 3: Decrypt selected ciphertext ec using kc
    bool decrypt_selected(const uint8_t e0[32], const uint8_t e1[32], uint8_t mc_out[32]);

    // Accessors for protocol inspection and cross-language verification
    const uint8_t* get_b() const { return b_.data(); }
    const uint8_t* get_B() const { return B_.data(); }
    const uint8_t* get_kc() const { return kc_.data(); }
    uint8_t get_choice() const { return choice_; }

private:
    std::array<uint8_t, 32> b_;
    std::array<uint8_t, 33> A_;
    std::array<uint8_t, 33> B_;
    std::array<uint8_t, 32> kc_;
    uint8_t choice_ = 0;
    bool computed_ = false;
};

} // namespace cot::ot
