/**
 * PointMath: Isolated mathematical helper for secp256k1 affine group arithmetic.
 * 
 * Scope strictly limited to:
 * - Compressed SEC1 decoding
 * - Compressed SEC1 encoding
 * - Affine point addition
 * - Affine point doubling
 * - Modular arithmetic helpers (modular inverse, square root mod p)
 * 
 * Note: Does NOT implement signing, ECDH, hashing, or random generation.
 * Cryptographic primitives are handled exclusively by Node.js core `crypto`.
 */

export const SECP256K1_FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
export const SECP256K1_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

export interface AffinePoint {
    x: bigint;
    y: bigint;
}

/**
 * Computes modular inverse: (a^-1) mod m via Extended Euclidean Algorithm.
 */
export function modInverse(a: bigint, m: bigint): bigint {
    a = (a % m + m) % m;
    if (a === 0n) {
        throw new Error('Cannot compute modular inverse of zero');
    }
    let [m0, y, x] = [m, 0n, 1n];
    while (a > 1n) {
        const q = a / m;
        let t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if (x < 0n) x += m0;
    return x;
}

/**
 * Computes modular exponentiation: (base^exp) mod m.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let res = 1n;
    base = (base % m + m) % m;
    while (exp > 0n) {
        if (exp & 1n) res = (res * base) % m;
        base = (base * base) % m;
        exp >>= 1n;
    }
    return res;
}

/**
 * Decodes and validates a 33-byte compressed SEC1 point on secp256k1.
 * Validates: prefix in {0x02, 0x03}, 0 <= x < p, and x^3 + 7 is a quadratic residue mod p.
 */
export function decodeCompressedPoint(buf: Uint8Array): AffinePoint {
    if (buf.length !== 33) {
        throw new Error(`Invalid point length: expected 33 bytes, got ${buf.length}`);
    }
    const prefix = buf[0];
    if (prefix !== 0x02 && prefix !== 0x03) {
        throw new Error(`Invalid compressed point prefix: expected 0x02 or 0x03, got 0x${prefix.toString(16)}`);
    }

    const hex = Buffer.from(buf.subarray(1, 33)).toString('hex');
    const x = BigInt('0x' + hex);
    if (x >= SECP256K1_FIELD_PRIME) {
        throw new Error(`X coordinate exceeds field prime p`);
    }

    // secp256k1 curve: y^2 = (x^3 + 7) mod p
    const y2 = (x * x % SECP256K1_FIELD_PRIME * x + 7n) % SECP256K1_FIELD_PRIME;

    // Modular square root for p = 3 mod 4: y = (y^2)^((p + 1) / 4) mod p
    const yExp = (SECP256K1_FIELD_PRIME + 1n) / 4n;
    let y = modPow(y2, yExp, SECP256K1_FIELD_PRIME);

    // Verify y is an actual square root of y2 mod p (Euler quadratic residue test)
    if (modPow(y, 2n, SECP256K1_FIELD_PRIME) !== y2) {
        throw new Error(`X coordinate does not correspond to a valid point on secp256k1 curve`);
    }

    // Match parity with SEC1 prefix: 0x02 = even (y & 1 == 0), 0x03 = odd (y & 1 == 1)
    const isOdd = (y & 1n) === 1n;
    const expectedOdd = prefix === 0x03;
    if (isOdd !== expectedOdd) {
        y = SECP256K1_FIELD_PRIME - y;
    }

    return { x, y };
}

/**
 * Encodes an affine point into 33-byte compressed SEC1 representation: [prefix 0x02/0x03] || [32-byte X].
 */
export function encodeCompressedPoint(pt: AffinePoint): Buffer {
    const prefix = (pt.y & 1n) === 1n ? 0x03 : 0x02;
    const buf = Buffer.alloc(33);
    buf[0] = prefix;
    const xHex = pt.x.toString(16).padStart(64, '0');
    Buffer.from(xHex, 'hex').copy(buf, 1);
    return buf;
}

/**
 * Point doubling on secp256k1 in affine coordinates: R = 2 * P.
 */
export function doublePoint(pt: AffinePoint): AffinePoint {
    const p = SECP256K1_FIELD_PRIME;
    if (pt.y === 0n) {
        throw new Error('Point doubling results in point at infinity');
    }
    // lambda = (3 * x^2) / (2 * y) mod p
    const num = (3n * pt.x % p * pt.x) % p;
    const den = (2n * pt.y) % p;
    const lambda = (num * modInverse(den, p)) % p;

    // x3 = lambda^2 - 2 * x mod p
    const x3 = ((lambda * lambda - 2n * pt.x) % p + p) % p;
    // y3 = lambda * (x - x3) - y mod p
    const y3 = ((lambda * (pt.x - x3) - pt.y) % p + p) % p;

    return { x: x3, y: y3 };
}

/**
 * Point addition on secp256k1 in affine coordinates: R = P1 + P2.
 */
export function addPoints(pt1: AffinePoint, pt2: AffinePoint): AffinePoint {
    const p = SECP256K1_FIELD_PRIME;
    if (pt1.x === pt2.x) {
        if (pt1.y === pt2.y) {
            return doublePoint(pt1);
        } else {
            throw new Error('Point addition results in point at infinity (P + (-P) = O)');
        }
    }

    // lambda = (y2 - y1) / (x2 - x1) mod p
    const dy = ((pt2.y - pt1.y) % p + p) % p;
    const dx = ((pt2.x - pt1.x) % p + p) % p;
    const lambda = (dy * modInverse(dx, p)) % p;

    // x3 = lambda^2 - x1 - x2 mod p
    const x3 = ((lambda * lambda - pt1.x - pt2.x) % p + p) % p;
    // y3 = lambda * (x1 - x3) - y1 mod p
    const y3 = ((lambda * (pt1.x - x3) - pt1.y) % p + p) % p;

    return { x: x3, y: y3 };
}
