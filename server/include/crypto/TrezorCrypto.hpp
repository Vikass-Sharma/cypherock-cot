#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>

namespace cot::crypto {

// secp256k1 field prime p = 2^256 - 2^32 - 977
// Used for: curve point coordinates (F_p), point addition slope lambda,
// OT message correlation, additive shares, and secret product verification.
extern const std::array<uint8_t, 32> SECP256K1_FIELD_PRIME_BE;

// secp256k1 curve order n
// Used for: order of base generator G (n * G = O), valid range of private scalars [1, n-1].
extern const std::array<uint8_t, 32> SECP256K1_CURVE_ORDER_BE;

// 1. Secure random 32-byte generation
// Platform integration: feeds Trezor's random_buffer() hook implemented via macOS arc4random_buf
void generate_random_32(uint8_t out[32]);

// 2. SHA-256 digest computation using Trezor sha256_Raw
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

// 3. Scalar validation (must be 1 <= scalar < n)
bool is_valid_scalar(const uint8_t scalar[32]);

// 4. secp256k1 generator multiplication: pub_key = scalar * G
// Returns false if scalar is invalid (0 or >= n)
bool scalar_multiply_base(const uint8_t priv_key[32], uint8_t pub_key_out[33]);

// 5. Point validation & decompression check
bool is_valid_point(const uint8_t point[33]);

// 6. ECDH shared secret derivation: computes 32-byte X coordinate of scalar * pub_key
// Trezor's ecdh_multiply produces uncompressed 65 bytes (0x04 || X || Y).
// This function explicitly extracts the 32-byte X-coordinate to normalize with Node.js computeSecret.
bool ecdh(const uint8_t priv_key[32], const uint8_t pub_key[33], uint8_t shared_secret_x[32]);

// 7. Point addition on secp256k1: out = p1 + p2
// Decompresses points, adds them in affine coordinates, and encodes to 33-byte compressed SEC1.
bool point_add(const uint8_t p1[33], const uint8_t p2[33], uint8_t out[33]);

// 8. Field arithmetic modulo p
// Addition: out = (a + b) mod p
void field_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

// Subtraction: out = (a - b) mod p
void field_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

// Multiplication: out = (a * b) mod p
void field_mul(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

// Formatting helper: bytes to lowercase hex string
std::string to_hex(const uint8_t* data, size_t len);

} // namespace cot::crypto
