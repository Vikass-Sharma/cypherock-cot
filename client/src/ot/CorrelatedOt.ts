import { NodeCrypto } from '../crypto/NodeCrypto';
import { BaseOtAlice, BaseOtBob } from './BaseOt';
import { SECP256K1_FIELD_PRIME } from '../crypto/PointMath';

export function isCanonicalFieldElement(val: Uint8Array): boolean {
    if (val.length !== 32) return false;
    const v = NodeCrypto.bytesToBigInt(val);
    return v < SECP256K1_FIELD_PRIME;
}

export function getLeBit(y: Uint8Array, bitIdx: number): number {
    if (bitIdx < 0 || bitIdx >= 256) return 0;
    const byteIdx = 31 - Math.floor(bitIdx / 8);
    const bitInByte = bitIdx % 8;
    return (y[byteIdx] >> bitInByte) & 1;
}

export function getPowerOfTwoModP(i: number): Buffer {
    let power = 1n;
    for (let step = 0; step < i; ++step) {
        power = (power * 2n) % SECP256K1_FIELD_PRIME;
    }
    return NodeCrypto.bigIntTo32Bytes(power);
}

function writeBeU32(val: number): Buffer {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(val, 0);
    return buf;
}

export function deriveDeterministicScalar(prefix: string, index: number): Buffer {
    let nonce = 0;
    const prefixBuf = Buffer.from(prefix, 'utf8');
    const idxBuf = writeBeU32(index);

    while (true) {
        const nonceBuf = writeBeU32(nonce);
        const input = Buffer.concat([prefixBuf, idxBuf, nonceBuf]);
        const hash = NodeCrypto.sha256(input);
        if (NodeCrypto.isValidScalar(hash)) {
            return hash;
        }
        nonce++;
    }
}

export function deriveDeterministicFieldElement(prefix: string, index: number): Buffer {
    const prefixBuf = Buffer.from(prefix, 'utf8');
    const idxBuf = writeBeU32(index);
    const input = Buffer.concat([prefixBuf, idxBuf]);
    const hash = NodeCrypto.sha256(input);
    return NodeCrypto.fieldAdd(hash, Buffer.alloc(32));
}

// ---------------------------------------------------------------------------
// CorrelatedOtAlice
// ---------------------------------------------------------------------------
export class CorrelatedOtAlice {
    private x: Buffer = Buffer.alloc(32);
    private Ui: Buffer[] = [];
    private m0: Buffer[] = [];
    private m1: Buffer[] = [];
    private initialized: boolean = false;

    constructor() {
        for (let i = 0; i < 256; ++i) {
            this.Ui.push(Buffer.alloc(32));
            this.m0.push(Buffer.alloc(32));
            this.m1.push(Buffer.alloc(32));
        }
    }

    public init(x: Uint8Array, deterministic: boolean = false): boolean {
        if (!isCanonicalFieldElement(x)) {
            return false;
        }
        this.x = Buffer.from(x);

        for (let i = 0; i < 256; ++i) {
            if (deterministic) {
                this.Ui[i] = deriveDeterministicFieldElement('COT_TEST_U_', i);
            } else {
                let randBuf: Buffer;
                do {
                    randBuf = NodeCrypto.generateRandom32();
                } while (!isCanonicalFieldElement(randBuf));
                this.Ui[i] = randBuf;
            }

            // m0_i = Ui
            this.m0[i] = Buffer.from(this.Ui[i]);

            // m1_i = (Ui + x) mod p
            this.m1[i] = NodeCrypto.fieldAdd(this.Ui[i], this.x);
        }

        this.initialized = true;
        return true;
    }

    public getM0(i: number): Buffer | null {
        if (i < 0 || i >= 256 || !this.initialized) return null;
        return this.m0[i];
    }

    public getM1(i: number): Buffer | null {
        if (i < 0 || i >= 256 || !this.initialized) return null;
        return this.m1[i];
    }

    public getUi(i: number): Buffer | null {
        if (i < 0 || i >= 256 || !this.initialized) return null;
        return this.Ui[i];
    }

    public getX(): Buffer {
        return this.x;
    }

    public computeShareU(): Buffer | null {
        if (!this.initialized) return null;

        let sum = 0n;
        let power = 1n;

        for (let i = 0; i < 256; ++i) {
            const uiVal = NodeCrypto.bytesToBigInt(this.Ui[i]);
            const term = (power * uiVal) % SECP256K1_FIELD_PRIME;
            sum = (sum + term) % SECP256K1_FIELD_PRIME;

            power = (power * 2n) % SECP256K1_FIELD_PRIME;
        }

        // U = -sum mod p = (0 - sum + p) mod p
        const uVal = (SECP256K1_FIELD_PRIME - sum) % SECP256K1_FIELD_PRIME;
        return NodeCrypto.bigIntTo32Bytes(uVal);
    }
}

// ---------------------------------------------------------------------------
// CorrelatedOtBob
// ---------------------------------------------------------------------------
export class CorrelatedOtBob {
    private y: Buffer = Buffer.alloc(32);
    private mc: Buffer[] = [];
    private mcRecorded: boolean[] = [];
    private initialized: boolean = false;

    constructor() {
        for (let i = 0; i < 256; ++i) {
            this.mc.push(Buffer.alloc(32));
            this.mcRecorded.push(false);
        }
    }

    public init(y: Uint8Array): boolean {
        if (!isCanonicalFieldElement(y)) {
            return false;
        }
        this.y = Buffer.from(y);
        for (let i = 0; i < 256; ++i) {
            this.mcRecorded[i] = false;
        }
        this.initialized = true;
        return true;
    }

    public getChoiceBit(i: number): number {
        if (i < 0 || i >= 256 || !this.initialized) return 0;
        return getLeBit(this.y, i);
    }

    public recordMc(i: number, mc: Uint8Array): boolean {
        if (i < 0 || i >= 256 || !this.initialized) return false;
        this.mc[i] = Buffer.from(mc);
        this.mcRecorded[i] = true;
        return true;
    }

    public getMc(i: number): Buffer | null {
        if (i < 0 || i >= 256 || !this.initialized || !this.mcRecorded[i]) return null;
        return this.mc[i];
    }

    public getY(): Buffer {
        return this.y;
    }

    public computeShareV(): Buffer | null {
        if (!this.initialized) return null;
        for (let i = 0; i < 256; ++i) {
            if (!this.mcRecorded[i]) return null;
        }

        let sum = 0n;
        let power = 1n;

        for (let i = 0; i < 256; ++i) {
            const mcVal = NodeCrypto.bytesToBigInt(this.mc[i]);
            const term = (power * mcVal) % SECP256K1_FIELD_PRIME;
            sum = (sum + term) % SECP256K1_FIELD_PRIME;

            power = (power * 2n) % SECP256K1_FIELD_PRIME;
        }

        return NodeCrypto.bigIntTo32Bytes(sum);
    }
}

// ---------------------------------------------------------------------------
// CorrelatedOtResult
// ---------------------------------------------------------------------------
export interface CorrelatedOtResult {
    success: boolean;
    baseOtCount: number;
    successfulMcCount: number;
    correlationCheckCount: number;
    U: Buffer;
    V: Buffer;
    expectedXy: Buffer;
    actualSum: Buffer;
    invariantPassed: boolean;
    errorMessage?: string;
}

// ---------------------------------------------------------------------------
// executeCorrelatedOt
// ---------------------------------------------------------------------------
export function executeCorrelatedOt(
    alice: CorrelatedOtAlice,
    bob: CorrelatedOtBob,
    deterministicOt: boolean = false
): CorrelatedOtResult {
    let baseOtCount = 0;
    let successfulMcCount = 0;
    let correlationCheckCount = 0;

    for (let i = 0; i < 256; ++i) {
        const baseAlice = new BaseOtAlice();
        const baseBob = new BaseOtBob();

        let detA: Buffer | undefined;
        let detB: Buffer | undefined;
        if (deterministicOt) {
            detA = deriveDeterministicScalar('COT_TEST_A_', i);
            detB = deriveDeterministicScalar('COT_TEST_B_', i);
        }

        // Alice Round 1: A = aG
        const A = baseAlice.init(detA);

        // Bob Round 2: Receives A, choice c_i = y_i, computes B, derives kc
        const choice = bob.getChoiceBit(i);
        const B = baseBob.receiveAAndComputeB(A, choice, detB);

        // Alice Round 2: Receives B, derives k0 and k1
        baseAlice.receiveB(B);

        // Alice Round 3: Encrypts m0 and m1
        const m0 = alice.getM0(i)!;
        const m1 = alice.getM1(i)!;
        const { e0, e1 } = baseAlice.encryptMessages(m0, m1);

        // Bob Round 3: Decrypts selected ciphertext
        const mc = baseBob.decryptSelected(e0, e1);

        // Bob records mc
        bob.recordMc(i, mc);

        baseOtCount++;

        // Verify Bob got expected selected message: mc == (choice ? m1 : m0)
        const expectedMc = (choice === 0) ? m0 : m1;
        if (mc.equals(expectedMc)) {
            successfulMcCount++;
        }

        // Verify correlation: (m1 - m0) mod p == x mod p
        const diff = NodeCrypto.fieldSub(m1, m0);
        if (diff.equals(alice.getX())) {
            correlationCheckCount++;
        }
    }

    const U = alice.computeShareU()!;
    const V = bob.computeShareV()!;

    // Compute expected x * y mod p
    const expectedXy = NodeCrypto.fieldMul(alice.getX(), bob.getY());

    // Compute actual (U + V) mod p
    const actualSum = NodeCrypto.fieldAdd(U, V);

    const invariantPassed = expectedXy.equals(actualSum);
    const success = invariantPassed && (successfulMcCount === 256) && (correlationCheckCount === 256);

    return {
        success,
        baseOtCount,
        successfulMcCount,
        correlationCheckCount,
        U,
        V,
        expectedXy,
        actualSum,
        invariantPassed
    };
}
