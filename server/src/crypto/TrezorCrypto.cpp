#include "crypto/TrezorCrypto.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

extern "C" {
#include "secp256k1.h"
#include "ecdsa.h"
#include "bignum.h"
#include "sha2.h"
#include "rand.h"
#include "memzero.h"
}

namespace cot::crypto {

// Field prime p = 2^256 - 2^32 - 977
const std::array<uint8_t, 32> SECP256K1_FIELD_PRIME_BE = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

// Curve order n
const std::array<uint8_t, 32> SECP256K1_CURVE_ORDER_BE = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

void generate_random_32(uint8_t out[32]) {
    // Calls Trezor's random_buffer hook, bridged to macOS arc4random_buf
    random_buffer(out, 32);
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256_Raw(data, len, out);
}

bool is_valid_scalar(const uint8_t scalar[32]) {
    bignum256 k = {0};
    bn_read_be(scalar, &k);
    if (bn_is_zero(&k) || !bn_is_less(&k, &secp256k1.order)) {
        memzero(&k, sizeof(k));
        return false;
    }
    memzero(&k, sizeof(k));
    return true;
}

bool scalar_multiply_base(const uint8_t priv_key[32], uint8_t pub_key_out[33]) {
    if (!is_valid_scalar(priv_key)) {
        return false;
    }
    return (ecdsa_get_public_key33(&secp256k1, priv_key, pub_key_out) == 0);
}

bool is_valid_point(const uint8_t point[33]) {
    if (point[0] != 0x02 && point[0] != 0x03) {
        return false;
    }
    curve_point pt = {0};
    int ret = ecdsa_read_pubkey(&secp256k1, point, &pt);
    memzero(&pt, sizeof(pt));
    return (ret != 0);
}

bool ecdh(const uint8_t priv_key[32], const uint8_t pub_key[33], uint8_t shared_secret_x[32]) {
    if (!is_valid_scalar(priv_key) || !is_valid_point(pub_key)) {
        return false;
    }
    uint8_t session_key[65] = {0};
    // Trezor ecdh_multiply computes uncompressed 0x04 || X || Y
    if (ecdh_multiply(&secp256k1, priv_key, pub_key, session_key) != 0) {
        memzero(session_key, sizeof(session_key));
        return false;
    }
    // Explicitly extract the 32-byte X coordinate to normalize with Node.js computeSecret
    std::memcpy(shared_secret_x, session_key + 1, 32);
    memzero(session_key, sizeof(session_key));
    return true;
}

bool point_add(const uint8_t p1[33], const uint8_t p2[33], uint8_t out[33]) {
    curve_point pt1 = {0}, pt2 = {0};
    if (!ecdsa_read_pubkey(&secp256k1, p1, &pt1) || !ecdsa_read_pubkey(&secp256k1, p2, &pt2)) {
        memzero(&pt1, sizeof(pt1));
        memzero(&pt2, sizeof(pt2));
        return false;
    }
    // Trezor point_add computes cp2 = cp1 + cp2
    ::point_add(&secp256k1, &pt1, &pt2);
    if (point_is_infinity(&pt2)) {
        memzero(&pt1, sizeof(pt1));
        memzero(&pt2, sizeof(pt2));
        return false;
    }
    compress_coords(&pt2, out);
    memzero(&pt1, sizeof(pt1));
    memzero(&pt2, sizeof(pt2));
    return true;
}

void field_add(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    bignum256 bna = {0}, bnb = {0};
    bn_read_be(a, &bna);
    bn_read_be(b, &bnb);
    bn_fast_mod(&bna, &secp256k1.prime);
    bn_mod(&bna, &secp256k1.prime);
    bn_fast_mod(&bnb, &secp256k1.prime);
    bn_mod(&bnb, &secp256k1.prime);

    bn_addmod(&bna, &bnb, &secp256k1.prime);
    bn_mod(&bna, &secp256k1.prime);
    bn_write_be(&bna, out);

    memzero(&bna, sizeof(bna));
    memzero(&bnb, sizeof(bnb));
}

void field_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    bignum256 bna = {0}, bnb = {0}, res = {0};
    bn_read_be(a, &bna);
    bn_read_be(b, &bnb);
    bn_fast_mod(&bna, &secp256k1.prime);
    bn_mod(&bna, &secp256k1.prime);
    bn_fast_mod(&bnb, &secp256k1.prime);
    bn_mod(&bnb, &secp256k1.prime);

    bn_subtractmod(&bna, &bnb, &res, &secp256k1.prime);
    bn_fast_mod(&res, &secp256k1.prime);
    bn_mod(&res, &secp256k1.prime);
    bn_write_be(&res, out);

    memzero(&bna, sizeof(bna));
    memzero(&bnb, sizeof(bnb));
    memzero(&res, sizeof(res));
}

void field_mul(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    bignum256 bna = {0}, bnb = {0};
    bn_read_be(a, &bna);
    bn_read_be(b, &bnb);
    bn_fast_mod(&bna, &secp256k1.prime);
    bn_mod(&bna, &secp256k1.prime);
    bn_fast_mod(&bnb, &secp256k1.prime);
    bn_mod(&bnb, &secp256k1.prime);

    // bn_multiply: x = k * x % prime
    bn_multiply(&bna, &bnb, &secp256k1.prime);
    bn_mod(&bnb, &secp256k1.prime);
    bn_write_be(&bnb, out);

    memzero(&bna, sizeof(bna));
    memzero(&bnb, sizeof(bnb));
}

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

} // namespace cot::crypto
