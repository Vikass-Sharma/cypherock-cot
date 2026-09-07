import * as crypto from 'crypto';
import {
    SECP256K1_FIELD_PRIME,
    SECP256K1_CURVE_ORDER,
    decodeCompressedPoint,
    encodeCompressedPoint,
    addPoints
} from './PointMath';

/**
 * NodeCrypto: Cryptographic operations wrapper using Node.js core `crypto` module.
 * 
 * Cryptographic operations (randomness, SHA-256, ECDH, base multiplication) are handled
 * by Node.js crypto. PointMath is used only for the mathematical point addition operation (B = bG + A).
 */
export class NodeCrypto {
    /**
     * Generates cryptographically secure 32 random bytes via Node.js crypto.
     */
    public static generateRandom32(): Buffer {
        return crypto.randomBytes(32);
    }

    /**
     * Computes SHA-256 digest via Node.js crypto.
     */
    public static sha256(data: Uint8Array): Buffer {
        return crypto.createHash('sha256').update(data).digest();
    }

    /**
     * Validates that scalar is in range [1, n - 1].
     */
    public static isValidScalar(scalar: Uint8Array): boolean {
        if (scalar.length !== 32) return false;
        const hex = Buffer.from(scalar).toString('hex');
        const val = BigInt('0x' + hex);
        return val >= 1n && val < SECP256K1_CURVE_ORDER;
    }

    /**
     * Computes public key from private scalar: pubKey = scalar * G.
     * Uses Node.js crypto.createECDH('secp256k1').
     */
    public static scalarMultiplyBase(privKey: Uint8Array): Buffer {
        if (!this.isValidScalar(privKey)) {
            throw new Error('Invalid private scalar: must be in range [1, n-1]');
        }
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(Buffer.from(privKey));
        return ecdh.getPublicKey(null, 'compressed');
    }

    /**
     * Validates 33-byte compressed SEC1 point on secp256k1.
     */
    public static isValidPoint(point: Uint8Array): boolean {
        if (point.length !== 33) return false;
        try {
            decodeCompressedPoint(point);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Computes ECDH shared secret: derives 32-byte X-coordinate of scalar * pubKey.
     * Uses Node.js crypto.createECDH('secp256k1').computeSecret(pubKey).
     */
    public static ecdh(privKey: Uint8Array, pubKey: Uint8Array): Buffer {
        if (!this.isValidScalar(privKey)) {
            throw new Error('Invalid private scalar for ECDH');
        }
        if (!this.isValidPoint(pubKey)) {
            throw new Error('Invalid public point for ECDH');
        }
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(Buffer.from(privKey));
        const secret = ecdh.computeSecret(Buffer.from(pubKey));
        if (secret.length !== 32) {
            throw new Error(`Unexpected ECDH secret length: ${secret.length}`);
        }
        return secret;
    }

    /**
     * Calculates B = bG + A using Node crypto for base multiplication (bG)
     * and PointMath for the affine group addition (+ A).
     */
    public static pointAdd(p1: Uint8Array, p2: Uint8Array): Buffer {
        const pt1 = decodeCompressedPoint(p1);
        const pt2 = decodeCompressedPoint(p2);
        const sum = addPoints(pt1, pt2);
        return encodeCompressedPoint(sum);
    }

    /**
     * Field addition modulo p: (a + b) mod p.
     */
    public static fieldAdd(a: Uint8Array, b: Uint8Array): Buffer {
        const va = this.bytesToBigInt(a);
        const vb = this.bytesToBigInt(b);
        const res = (va + vb) % SECP256K1_FIELD_PRIME;
        return this.bigIntTo32Bytes(res);
    }

    /**
     * Field subtraction modulo p: (a - b) mod p.
     */
    public static fieldSub(a: Uint8Array, b: Uint8Array): Buffer {
        const va = this.bytesToBigInt(a);
        const vb = this.bytesToBigInt(b);
        const res = ((va - vb) % SECP256K1_FIELD_PRIME + SECP256K1_FIELD_PRIME) % SECP256K1_FIELD_PRIME;
        return this.bigIntTo32Bytes(res);
    }

    /**
     * Field multiplication modulo p: (a * b) mod p.
     */
    public static fieldMul(a: Uint8Array, b: Uint8Array): Buffer {
        const va = this.bytesToBigInt(a);
        const vb = this.bytesToBigInt(b);
        const res = (va * vb) % SECP256K1_FIELD_PRIME;
        return this.bigIntTo32Bytes(res);
    }

    public static bytesToBigInt(buf: Uint8Array): bigint {
        if (buf.length === 0) return 0n;
        return BigInt('0x' + Buffer.from(buf).toString('hex'));
    }

    public static bigIntTo32Bytes(val: bigint): Buffer {
        const hex = (val % SECP256K1_FIELD_PRIME).toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex');
    }
}
