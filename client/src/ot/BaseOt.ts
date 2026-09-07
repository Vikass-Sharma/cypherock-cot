import { NodeCrypto } from '../crypto/NodeCrypto';

/**
 * Concrete encryption/masking instantiation used for the mock implementation;
 * the COT.pdf specifies the use of the OT-derived keys but does not prescribe
 * this exact masking construction.
 *
 * 1. Convert key to 32 bytes
 * 2. Derive 32-byte mask using SHA256(key || uint32_be(index))
 * 3. Interpret mask as field element mod p
 * 4. Encrypt: e = (m + mask) mod p
 * 5. Decrypt: m = (e - mask) mod p
 */
export function deriveOtMask(key: Uint8Array, index: number): Buffer {
    if (key.length !== 32) {
        throw new Error(`Invalid key length: expected 32 bytes, got ${key.length}`);
    }
    const idxBuf = Buffer.alloc(4);
    idxBuf.writeUInt32BE(index, 0);

    const hash = NodeCrypto.sha256(Buffer.concat([Buffer.from(key), idxBuf]));
    // Reduce hash modulo p
    const zero = Buffer.alloc(32);
    return NodeCrypto.fieldAdd(hash, zero);
}

export function encryptOtMessage(m: Uint8Array, key: Uint8Array, index: number): Buffer {
    if (m.length !== 32) {
        throw new Error(`Invalid message length: expected 32 bytes, got ${m.length}`);
    }
    const mask = deriveOtMask(key, index);
    return NodeCrypto.fieldAdd(m, mask);
}

export function decryptOtMessage(e: Uint8Array, key: Uint8Array, index: number): Buffer {
    if (e.length !== 32) {
        throw new Error(`Invalid ciphertext length: expected 32 bytes, got ${e.length}`);
    }
    const mask = deriveOtMask(key, index);
    return NodeCrypto.fieldSub(e, mask);
}

// ---------------------------------------------------------------------------
// Alice (Server) for Base OT (COT.pdf Appendix A.3.1)
// ---------------------------------------------------------------------------
export class BaseOtAlice {
    private a: Buffer = Buffer.alloc(32);
    private A: Buffer = Buffer.alloc(33);
    private B: Buffer = Buffer.alloc(33);
    private B_minus_A: Buffer = Buffer.alloc(33);
    private k0: Buffer = Buffer.alloc(32);
    private k1: Buffer = Buffer.alloc(32);
    private initialized: boolean = false;
    private keysDerived: boolean = false;

    /**
     * Round 1: Generate ephemeral scalar a in [1, n-1] and compute A = a*G (33 bytes)
     */
    public init(deterministicA?: Uint8Array): Buffer {
        if (deterministicA) {
            if (!NodeCrypto.isValidScalar(deterministicA)) {
                throw new Error('Invalid scalar for Alice ephemeral private key');
            }
            this.a = Buffer.from(deterministicA);
        } else {
            do {
                this.a = NodeCrypto.generateRandom32();
            } while (!NodeCrypto.isValidScalar(this.a));
        }

        this.A = NodeCrypto.scalarMultiplyBase(this.a);
        this.initialized = true;
        this.keysDerived = false;
        return this.A;
    }

    /**
     * Round 2: Receive public point B from Bob, compute k0 = (aB)_x and k1 = (a(B-A))_x
     */
    public receiveB(B: Uint8Array): { k0: Buffer; k1: Buffer; B_minus_A: Buffer } {
        if (!this.initialized) {
            throw new Error('Alice must be initialized before receiving B');
        }
        if (!NodeCrypto.isValidPoint(B)) {
            throw new Error('Invalid public point B received by Alice');
        }
        this.B = Buffer.from(B);

        // 1. k0 = (a * B)_x
        this.k0 = NodeCrypto.ecdh(this.a, this.B);

        // 2. Compute -A: invert parity prefix (0x02 <-> 0x03)
        const negA = Buffer.from(this.A);
        negA[0] = negA[0] === 0x02 ? 0x03 : 0x02;

        // 3. Compute B - A = B + (-A)
        this.B_minus_A = NodeCrypto.pointAdd(this.B, negA);

        // 4. k1 = (a * (B - A))_x
        this.k1 = NodeCrypto.ecdh(this.a, this.B_minus_A);

        this.keysDerived = true;
        return { k0: this.k0, k1: this.k1, B_minus_A: this.B_minus_A };
    }

    /**
     * Round 3: Encrypt m0 with k0 and m1 with k1
     */
    public encryptMessages(m0: Uint8Array, m1: Uint8Array): { e0: Buffer; e1: Buffer } {
        if (!this.keysDerived) {
            throw new Error('Alice must derive keys before encrypting messages');
        }
        const e0 = encryptOtMessage(m0, this.k0, 0);
        const e1 = encryptOtMessage(m1, this.k1, 1);
        return { e0, e1 };
    }

    public getA(): Buffer { return this.A; }
    public getK0(): Buffer { return this.k0; }
    public getK1(): Buffer { return this.k1; }
    public getBMinusA(): Buffer { return this.B_minus_A; }
}

// ---------------------------------------------------------------------------
// Bob (Client) for Base OT (COT.pdf Appendix A.3.1)
// ---------------------------------------------------------------------------
export class BaseOtBob {
    private b: Buffer = Buffer.alloc(32);
    private A: Buffer = Buffer.alloc(33);
    private B: Buffer = Buffer.alloc(33);
    private kc: Buffer = Buffer.alloc(32);
    private choice: number = 0;
    private computed: boolean = false;

    /**
     * Round 2: Receive A, generate ephemeral scalar b, compute B = bG (c=0) or B = bG + A (c=1),
     * and derive decryption key kc = (bA)_x
     */
    public receiveAAndComputeB(A: Uint8Array, choiceBit: number, deterministicB?: Uint8Array): Buffer {
        if (!NodeCrypto.isValidPoint(A)) {
            throw new Error('Invalid public point A received by Bob');
        }
        if (choiceBit !== 0 && choiceBit !== 1) {
            throw new Error(`Invalid choice bit: expected 0 or 1, got ${choiceBit}`);
        }

        this.A = Buffer.from(A);
        this.choice = choiceBit;

        if (deterministicB) {
            if (!NodeCrypto.isValidScalar(deterministicB)) {
                throw new Error('Invalid scalar for Bob ephemeral private key');
            }
            this.b = Buffer.from(deterministicB);
        } else {
            do {
                this.b = NodeCrypto.generateRandom32();
            } while (!NodeCrypto.isValidScalar(this.b));
        }

        const bG = NodeCrypto.scalarMultiplyBase(this.b);

        if (this.choice === 0) {
            // B = bG
            this.B = bG;
        } else {
            // B = bG + A
            this.B = NodeCrypto.pointAdd(bG, this.A);
        }

        // kc = (b * A)_x
        this.kc = NodeCrypto.ecdh(this.b, this.A);

        this.computed = true;
        return this.B;
    }

    /**
     * Round 3: Decrypt selected ciphertext ec using kc
     */
    public decryptSelected(e0: Uint8Array, e1: Uint8Array): Buffer {
        if (!this.computed) {
            throw new Error('Bob must compute B and kc before decrypting');
        }
        const ec = (this.choice === 0) ? e0 : e1;
        return decryptOtMessage(ec, this.kc, this.choice);
    }

    public getB(): Buffer { return this.B; }
    public getKc(): Buffer { return this.kc; }
    public getChoice(): number { return this.choice; }
}
