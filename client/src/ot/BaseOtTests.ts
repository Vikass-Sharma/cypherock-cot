import * as assert from 'assert';
import { BaseOtAlice, BaseOtBob, decryptOtMessage } from './BaseOt';
import { NodeCrypto } from '../crypto/NodeCrypto';
import { SECP256K1_CURVE_ORDER, SECP256K1_FIELD_PRIME } from '../crypto/PointMath';

export interface BaseOtReport {
    allPassed: boolean;
}

export function runBaseOtUnitTests(): BaseOtReport {
    console.log('=============================================================');
    console.log(' Stage 5: Base Oblivious Transfer (COT.pdf Appendix A.3.1)');
    console.log('=============================================================\n');

    let allPassed = true;

    const checkTest = (name: string, condition: boolean, info: string = '') => {
        console.log(`  - [${condition ? 'PASS' : 'FAIL'}] ${name}${info ? ' -> ' + info : ''}`);
        if (!condition) allPassed = false;
    };

    // Deterministic test inputs
    const detA = Buffer.alloc(32); detA[31] = 7;
    const m0 = Buffer.alloc(32, 0x11);
    const m1 = Buffer.alloc(32, 0x22);

    // -----------------------------------------------------------------------
    // Test 1: Deterministic Base OT with choice c = 0
    // -----------------------------------------------------------------------
    console.log('--- Deterministic Base OT Test: choice c = 0 ---');
    {
        const detB0 = Buffer.alloc(32); detB0[31] = 11;
        const choice = 0;

        const alice = new BaseOtAlice();
        const A = alice.init(detA);
        checkTest('Alice init (a=7)', A.length === 33, `A=${A.toString('hex')}`);

        const bob = new BaseOtBob();
        const B0 = bob.receiveAAndComputeB(A, choice, detB0);
        checkTest('Bob receive A & compute B (b=11, c=0)', B0.length === 33, `B=${B0.toString('hex')}`);

        const { k0, k1, B_minus_A } = alice.receiveB(B0);
        checkTest('Alice receive B & derive keys', k0.length === 32 && k1.length === 32,
                  `k0=${k0.toString('hex')}, k1=${k1.toString('hex')}`);

        // Critical algebra checks
        const k0Match = k0.equals(bob.getKc());
        const k1Mismatch = !k1.equals(bob.getKc());
        checkTest('Algebra check: k0 == kc (c=0)', k0Match, `kc=${bob.getKc().toString('hex')}`);
        checkTest('Algebra check: k1 != kc (c=0)', k1Mismatch);

        // Round 3: Alice encrypts m0 and m1
        const { e0, e1 } = alice.encryptMessages(m0, m1);
        checkTest('Alice encrypt messages (m0, m1)', e0.length === 32 && e1.length === 32,
                  `e0=${e0.toString('hex')}, e1=${e1.toString('hex')}`);

        // Bob decrypts selected ciphertext e0 with kc
        const mc = bob.decryptSelected(e0, e1);
        const msgMatch = mc.equals(m0);
        checkTest('Bob decrypt selected: mc == m0 (c=0)', msgMatch, `Recovered: ${mc.toString('hex')}`);

        // Wrong-key decryption check
        const wrongDec = decryptOtMessage(e1, bob.getKc(), 1);
        const wrongKeyFails = !wrongDec.equals(m1);
        checkTest('Security check: unused ciphertext e1 cannot be decrypted with kc', wrongKeyFails);
    }
    console.log();

    // -----------------------------------------------------------------------
    // Test 2: Deterministic Base OT with choice c = 1
    // -----------------------------------------------------------------------
    console.log('--- Deterministic Base OT Test: choice c = 1 ---');
    {
        const detB1 = Buffer.alloc(32); detB1[31] = 13;
        const choice = 1;

        const alice = new BaseOtAlice();
        const A = alice.init(detA);
        checkTest('Alice init (a=7)', A.length === 33, `A=${A.toString('hex')}`);

        const bob = new BaseOtBob();
        const B1 = bob.receiveAAndComputeB(A, choice, detB1);
        checkTest('Bob receive A & compute B (b=13, c=1)', B1.length === 33, `B=${B1.toString('hex')}`);

        const { k0, k1, B_minus_A } = alice.receiveB(B1);
        checkTest('Alice receive B & derive keys', k0.length === 32 && k1.length === 32,
                  `k0=${k0.toString('hex')}, k1=${k1.toString('hex')}`);

        // Critical algebra checks
        const k1Match = k1.equals(bob.getKc());
        const k0Mismatch = !k0.equals(bob.getKc());
        checkTest('Algebra check: k1 == kc (c=1)', k1Match, `kc=${bob.getKc().toString('hex')}`);
        checkTest('Algebra check: k0 != kc (c=1)', k0Mismatch);

        // Round 3: Alice encrypts m0 and m1
        const { e0, e1 } = alice.encryptMessages(m0, m1);
        checkTest('Alice encrypt messages (m0, m1)', e0.length === 32 && e1.length === 32,
                  `e0=${e0.toString('hex')}, e1=${e1.toString('hex')}`);

        // Bob decrypts selected ciphertext e1 with kc
        const mc = bob.decryptSelected(e0, e1);
        const msgMatch = mc.equals(m1);
        checkTest('Bob decrypt selected: mc == m1 (c=1)', msgMatch, `Recovered: ${mc.toString('hex')}`);

        // Wrong-key decryption check
        const wrongDec = decryptOtMessage(e0, bob.getKc(), 0);
        const wrongKeyFails = !wrongDec.equals(m0);
        checkTest('Security check: unused ciphertext e0 cannot be decrypted with kc', wrongKeyFails);
    }
    console.log();

    // -----------------------------------------------------------------------
    // Test 3: Multiple Random In-Memory Protocol Iterations
    // -----------------------------------------------------------------------
    console.log('--- Random In-Memory Protocol Executions (5 runs) ---');
    {
        let allRandomOk = true;
        for (let run = 1; run <= 5; run++) {
            const randM0 = NodeCrypto.generateRandom32();
            const randM1 = NodeCrypto.generateRandom32();
            const randChoice = NodeCrypto.generateRandom32()[0] & 1;

            const alice = new BaseOtAlice();
            const A = alice.init();

            const bob = new BaseOtBob();
            const B = bob.receiveAAndComputeB(A, randChoice);

            alice.receiveB(B);

            const { e0, e1 } = alice.encryptMessages(randM0, randM1);
            const mc = bob.decryptSelected(e0, e1);

            const expectedM = (randChoice === 0) ? randM0 : randM1;
            if (!mc.equals(expectedM)) {
                allRandomOk = false;
            }
        }
        checkTest('5 independent random Base OT protocol runs', allRandomOk, 'All 5 recovered mc successfully');
    }
    console.log();

    // -----------------------------------------------------------------------
    // Test 4: Negative & Boundary Tests
    // -----------------------------------------------------------------------
    console.log('--- Base OT Negative / Boundary Tests ---');
    {
        const alice = new BaseOtAlice();
        const validA = alice.init();
        const bob = new BaseOtBob();

        // 1. Invalid choice bit (c = 2)
        let rejChoice2 = false;
        try {
            bob.receiveAAndComputeB(validA, 2);
        } catch {
            rejChoice2 = true;
        }
        checkTest('Reject invalid choice bit c = 2', rejChoice2);

        // 2. Invalid choice bit (c = 255)
        let rejChoice255 = false;
        try {
            bob.receiveAAndComputeB(validA, 255);
        } catch {
            rejChoice255 = true;
        }
        checkTest('Reject invalid choice bit c = 255', rejChoice255);

        // 3. Malformed point A with bad prefix 0x01
        const badA = Buffer.from(validA);
        badA[0] = 0x01;
        let rejBadA = false;
        try {
            bob.receiveAAndComputeB(badA, 0);
        } catch {
            rejBadA = true;
        }
        checkTest('Reject malformed point A with bad prefix 0x01', rejBadA);

        // 4. Malformed point B not on curve
        const badB = Buffer.alloc(33);
        badB[0] = 0x02;
        badB[32] = 0x05;
        let rejBadB = false;
        try {
            alice.receiveB(badB);
        } catch {
            rejBadB = true;
        }
        checkTest('Reject malformed point B not on curve', rejBadB);

        // 5. Scalar == 0 for Alice init
        const zeroScalar = Buffer.alloc(32);
        let rejZeroScalar = false;
        try {
            const badAlice = new BaseOtAlice();
            badAlice.init(zeroScalar);
        } catch {
            rejZeroScalar = true;
        }
        checkTest('Reject scalar == 0 for Alice init', rejZeroScalar);

        // 6. Scalar == n for Alice init
        const nHex = SECP256K1_CURVE_ORDER.toString(16).padStart(64, '0');
        const nScalar = Buffer.from(nHex, 'hex');
        let rejNScalar = false;
        try {
            const badAlice = new BaseOtAlice();
            badAlice.init(nScalar);
        } catch {
            rejNScalar = true;
        }
        checkTest('Reject scalar == n for Alice init', rejNScalar);

        // 7. Scalar == p - 1 for Alice init (since p - 1 > n)
        const pMinus1Hex = (SECP256K1_FIELD_PRIME - 1n).toString(16).padStart(64, '0');
        const pMinus1Scalar = Buffer.from(pMinus1Hex, 'hex');
        let rejPMinus1 = false;
        try {
            const badAlice = new BaseOtAlice();
            badAlice.init(pMinus1Scalar);
        } catch {
            rejPMinus1 = true;
        }
        checkTest('Reject scalar == p - 1 for Alice init', rejPMinus1);

        // 8. Wrong length point
        let rejWrongLenPoint = false;
        try {
            bob.receiveAAndComputeB(Buffer.alloc(32), 0);
        } catch {
            rejWrongLenPoint = true;
        }
        checkTest('Reject wrong-length point (32 bytes)', rejWrongLenPoint);

        // 9. Wrong length scalar
        let rejWrongLenScalar = false;
        try {
            const badAlice = new BaseOtAlice();
            badAlice.init(Buffer.alloc(31));
        } catch {
            rejWrongLenScalar = true;
        }
        checkTest('Reject wrong-length scalar (31 bytes)', rejWrongLenScalar);
    }

    console.log('\n=============================================================');
    console.log(` Stage 5 TypeScript Base OT Test Result: ${allPassed ? 'ALL PASSED' : 'FAILED'}`);
    console.log('=============================================================\n');

    return { allPassed };
}
