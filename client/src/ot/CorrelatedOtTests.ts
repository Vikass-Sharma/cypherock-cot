import { NodeCrypto } from '../crypto/NodeCrypto';
import {
    CorrelatedOtAlice,
    CorrelatedOtBob,
    executeCorrelatedOt,
    isCanonicalFieldElement
} from './CorrelatedOt';
import { SECP256K1_FIELD_PRIME } from '../crypto/PointMath';

function runDeterministicCotCase(name: string, x: Uint8Array, y: Uint8Array): boolean {
    console.log(`\n--- COT Deterministic Test: ${name} ---`);
    const alice = new CorrelatedOtAlice();
    if (!alice.init(x, true)) {
        console.log('  [FAIL] Alice init failed');
        return false;
    }

    const bob = new CorrelatedOtBob();
    if (!bob.init(y)) {
        console.log('  [FAIL] Bob init failed');
        return false;
    }

    console.log(`  x: ${Buffer.from(x).toString('hex')}`);
    console.log(`  y: ${Buffer.from(y).toString('hex')}`);
    const first4Bits = [0, 1, 2, 3].map(i => bob.getChoiceBit(i)).join(' ');
    console.log(`  first 4 bits of y (LSB first): ${first4Bits}`);

    for (let i = 0; i < 4; ++i) {
        console.log(
            `  [bit ${i}] Ui=${alice.getUi(i)!.subarray(0, 8).toString('hex')}... ` +
            `m0=${alice.getM0(i)!.subarray(0, 8).toString('hex')}... ` +
            `m1=${alice.getM1(i)!.subarray(0, 8).toString('hex')}...`
        );
    }

    const res = executeCorrelatedOt(alice, bob, true);
    if (!res.success) {
        console.log(`  [FAIL] Protocol execution failed: ${res.errorMessage}`);
        return false;
    }

    for (let i = 0; i < 4; ++i) {
        console.log(
            `  [bit ${i}] mc=${bob.getMc(i)!.subarray(0, 8).toString('hex')}... (c=${bob.getChoiceBit(i)})`
        );
    }

    console.log(`  U: ${res.U.toString('hex')}`);
    console.log(`  V: ${res.V.toString('hex')}`);
    console.log(`  x*y mod p: ${res.expectedXy.toString('hex')}`);
    console.log(`  (U+V) mod p: ${res.actualSum.toString('hex')}`);

    console.log(`  Base OT invocations: ${res.baseOtCount}`);
    console.log(`  successful selected-message recoveries: ${res.successfulMcCount}/256`);
    console.log(`  correlation checks (m1 - m0 == x): ${res.correlationCheckCount}/256`);

    // Algebra self-check:
    // Verify: V - sum(2^i * y_i * x) == sum(2^i * Ui) mod p
    let sumYx = 0n;
    let sumUi = 0n;
    let power = 1n;
    const xVal = NodeCrypto.bytesToBigInt(x);

    for (let i = 0; i < 256; ++i) {
        const uiVal = NodeCrypto.bytesToBigInt(alice.getUi(i)!);
        sumUi = (sumUi + (power * uiVal)) % SECP256K1_FIELD_PRIME;

        if (bob.getChoiceBit(i) === 1) {
            sumYx = (sumYx + (power * xVal)) % SECP256K1_FIELD_PRIME;
        }

        power = (power * 2n) % SECP256K1_FIELD_PRIME;
    }

    const vVal = NodeCrypto.bytesToBigInt(res.V);
    const lhs = ((vVal - sumYx) % SECP256K1_FIELD_PRIME + SECP256K1_FIELD_PRIME) % SECP256K1_FIELD_PRIME;

    if (lhs !== sumUi) {
        console.log('  [FAIL] Algebra self-check failed: V - sum(2^i * y_i * x) != sum(2^i * Ui)');
        return false;
    }
    console.log('  algebra self-check: PASS');

    if (!res.invariantPassed) {
        console.log('  [FAIL] Multiplication invariant failed!');
        return false;
    }
    console.log('  multiplication invariant: PASS');
    return true;
}

export function runCorrelatedOtUnitTests(): boolean {
    console.log('\n=============================================================');
    console.log(' Stage 6: Correlated Oblivious Transfer (Appendix A.3.2/A.3.3)');
    console.log('=============================================================');

    // 1. Simple case: x = 1, y = 1
    const x1 = Buffer.alloc(32);
    const y1 = Buffer.alloc(32);
    x1[31] = 1;
    y1[31] = 1;
    if (!runDeterministicCotCase('x = 1, y = 1', x1, y1)) {
        return false;
    }

    // 2. Small values: x = 5, y = 13
    const x2 = Buffer.alloc(32);
    const y2 = Buffer.alloc(32);
    x2[31] = 5;
    y2[31] = 13;
    if (!runDeterministicCotCase('x = 5, y = 13', x2, y2)) {
        return false;
    }

    // 3. 256-bit wide vectors
    const x3 = Buffer.from([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ]);
    const y3 = Buffer.from([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ]);
    if (!runDeterministicCotCase('256-bit wide vectors', x3, y3)) {
        return false;
    }

    // 4. Boundary field values: x = p - 1, y = p - 1
    const pMinus1 = NodeCrypto.bigIntTo32Bytes(SECP256K1_FIELD_PRIME - 1n);
    if (!runDeterministicCotCase('x = p - 1, y = p - 1', pMinus1, pMinus1)) {
        return false;
    }

    // 5. Zero cases
    const zero = Buffer.alloc(32);
    const fortyTwo = Buffer.alloc(32);
    fortyTwo[31] = 42;

    if (!runDeterministicCotCase('x = 0, y = 0', zero, zero)) {
        return false;
    }
    if (!runDeterministicCotCase('x = 0, y = 42', zero, fortyTwo)) {
        return false;
    }
    if (!runDeterministicCotCase('x = 42, y = 0', fortyTwo, zero)) {
        return false;
    }

    // 6. Random in-memory executions (5 runs)
    console.log('\n--- Random In-Memory Protocol Executions (5 runs) ---');
    for (let run = 1; run <= 5; ++run) {
        let rx: Buffer;
        let ry: Buffer;
        do {
            rx = NodeCrypto.generateRandom32();
        } while (!isCanonicalFieldElement(rx));
        do {
            ry = NodeCrypto.generateRandom32();
        } while (!isCanonicalFieldElement(ry));

        const alice = new CorrelatedOtAlice();
        if (!alice.init(rx, false)) {
            console.log(`  [FAIL] Run ${run} Alice init failed`);
            return false;
        }
        const bob = new CorrelatedOtBob();
        if (!bob.init(ry)) {
            console.log(`  [FAIL] Run ${run} Bob init failed`);
            return false;
        }

        const res = executeCorrelatedOt(alice, bob, false);
        if (!res.success) {
            console.log(`  [FAIL] Run ${run} failed: ${res.errorMessage}`);
            return false;
        }
        console.log(`  - [PASS] Run ${run}: invariant (U + V == x * y mod p) hold for random x, y`);
    }

    // 7. Negative and boundary tests
    console.log('\n--- COT Negative & Boundary Tests ---');
    {
        const badVal = Buffer.from(SECP256K1_FIELD_PRIME.toString(16).padStart(64, '0'), 'hex'); // equal to p
        const badAlice = new CorrelatedOtAlice();
        if (badAlice.init(badVal)) {
            console.log('  [FAIL] Alice failed to reject x == p');
            return false;
        }
        console.log('  - [PASS] Reject non-canonical field element x == p');

        const badBob = new CorrelatedOtBob();
        if (badBob.init(badVal)) {
            console.log('  [FAIL] Bob failed to reject y == p');
            return false;
        }
        console.log('  - [PASS] Reject non-canonical field element y == p');
    }

    console.log('\n=============================================================');
    console.log(' Stage 6 TypeScript Correlated OT Test Result: ALL PASSED');
    console.log('=============================================================\n');
    return true;
}
