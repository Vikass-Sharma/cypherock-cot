import * as assert from 'assert';
import { NodeCrypto } from './NodeCrypto';
import { SECP256K1_FIELD_PRIME, SECP256K1_CURVE_ORDER } from './PointMath';

export interface TestReportItem {
    name: string;
    input: string;
    expected: string;
    actual: string;
    passed: boolean;
}

export function runCryptoUnitTests(): { allPassed: boolean; reports: TestReportItem[] } {
    console.log('=============================================================');
    console.log(' Stage 4: Cryptographic Primitives Validation (Client/Node)');
    console.log('=============================================================\n');

    let allPassed = true;
    const reports: TestReportItem[] = [];

    const recordTest = (name: string, input: string, expected: string, actual: string, condition: boolean) => {
        reports.push({
            name,
            input,
            expected,
            actual,
            passed: condition
        });
        console.log(`  - [${condition ? 'PASS' : 'FAIL'}] ${name} -> ${actual}`);
        if (!condition) allPassed = false;
    };

    // A. Secure random 32-byte values
    {
        const r1 = NodeCrypto.generateRandom32();
        const r2 = NodeCrypto.generateRandom32();
        const cond = r1.length === 32 && r2.length === 32 && !r1.equals(r2);
        recordTest(
            'A. Random 32-byte Generation',
            'None',
            '32 non-zero cryptographically secure bytes',
            `Len: ${r1.length}, Sample: ${r1.subarray(0, 4).toString('hex')}...`,
            cond
        );
    }

    // B. SHA-256
    {
        // Vector 1: Empty string
        const d1 = NodeCrypto.sha256(Buffer.alloc(0)).toString('hex');
        const exp1 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        recordTest('B. SHA-256 (Empty string)', '""', exp1, d1, d1 === exp1);

        // Vector 2: "abc"
        const d2 = NodeCrypto.sha256(Buffer.from('abc')).toString('hex');
        const exp2 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
        recordTest('B. SHA-256 ("abc")', '"abc"', exp2, d2, d2 === exp2);
    }

    // C. secp256k1 generator multiplication
    let pubG: Buffer = Buffer.alloc(0);
    let pub2G: Buffer = Buffer.alloc(0);
    let pub3G: Buffer = Buffer.alloc(0);
    {
        // 1 * G
        const priv1 = Buffer.alloc(32); priv1[31] = 1;
        pubG = NodeCrypto.scalarMultiplyBase(priv1);
        const expG = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
        recordTest('C. Generator mult (priv=1 -> G)', 'scalar=1', expG, pubG.toString('hex'), pubG.toString('hex') === expG);

        // 2 * G
        const priv2 = Buffer.alloc(32); priv2[31] = 2;
        pub2G = NodeCrypto.scalarMultiplyBase(priv2);
        const exp2G = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
        recordTest('C. Generator mult (priv=2 -> 2G)', 'scalar=2', exp2G, pub2G.toString('hex'), pub2G.toString('hex') === exp2G);

        // 3 * G
        const priv3 = Buffer.alloc(32); priv3[31] = 3;
        pub3G = NodeCrypto.scalarMultiplyBase(priv3);
        const exp3G = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
        recordTest('C. Generator mult (priv=3 -> 3G)', 'scalar=3', exp3G, pub3G.toString('hex'), pub3G.toString('hex') === exp3G);
    }

    // D. ECDH shared-secret calculation (Alice priv = 2, Bob priv = 3 -> 6G)
    {
        const privAlice = Buffer.alloc(32); privAlice[31] = 2;
        const privBob = Buffer.alloc(32); privBob[31] = 3;

        const secretAlice = NodeCrypto.ecdh(privAlice, pub3G);
        const secretBob = NodeCrypto.ecdh(privBob, pub2G);

        const exp6G = 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556';
        const match = secretAlice.equals(secretBob) && secretAlice.toString('hex') === exp6G;
        recordTest(
            'D. ECDH shared secret (2 * 3G == 3 * 2G == X(6G))',
            'Alice priv=2, Bob priv=3',
            exp6G,
            secretAlice.toString('hex'),
            match
        );
    }

    // E. EC point encoding
    {
        const validG = NodeCrypto.isValidPoint(pubG);
        const valid2G = NodeCrypto.isValidPoint(pub2G);
        const prefixOk = pubG[0] === 0x02 || pubG[0] === 0x03;
        const cond = validG && valid2G && prefixOk && pubG.length === 33;
        recordTest(
            'E. EC point encoding (33 bytes SEC1 compressed)',
            'Base point G',
            'Valid 33-byte SEC1 (prefix 0x02/0x03 + 32-byte X)',
            `Prefix: 0x0${pubG[0]}, len: ${pubG.length}`,
            cond
        );
    }

    // F. EC point addition (2G + 3G = 5G)
    {
        const sumPoint = NodeCrypto.pointAdd(pub2G, pub3G);
        const priv5 = Buffer.alloc(32); priv5[31] = 5;
        const pub5G = NodeCrypto.scalarMultiplyBase(priv5);
        const exp5G = '022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4';

        const match5G = sumPoint.equals(pub5G) && sumPoint.toString('hex') === exp5G;
        recordTest(
            'F. Point addition (2G + 3G == 5G)',
            'p1 = 2G, p2 = 3G',
            exp5G,
            sumPoint.toString('hex'),
            match5G
        );
    }

    // G. Modular arithmetic modulo p
    {
        const pMinus1Val = SECP256K1_FIELD_PRIME - 1n;
        const pMinus1Buf = Buffer.from(pMinus1Val.toString(16).padStart(64, '0'), 'hex');
        const twoBuf = Buffer.alloc(32); twoBuf[31] = 2;
        const oneBuf = Buffer.alloc(32); oneBuf[31] = 1;

        // 1. Add: (p - 1) + 2 mod p == 1
        const addRes = NodeCrypto.fieldAdd(pMinus1Buf, twoBuf);
        const expAdd = '0000000000000000000000000000000000000000000000000000000000000001';
        recordTest('G. Field Add ((p - 1) + 2 mod p == 1)', 'a = p - 1, b = 2', expAdd, addRes.toString('hex'), addRes.toString('hex') === expAdd);

        // 2. Sub: 1 - 2 mod p == p - 1
        const subRes = NodeCrypto.fieldSub(oneBuf, twoBuf);
        const expSub = pMinus1Buf.toString('hex');
        recordTest('G. Field Sub (1 - 2 mod p == p - 1)', 'a = 1, b = 2', expSub, subRes.toString('hex'), subRes.toString('hex') === expSub);

        // 3. Mul: (p - 1) * (p - 1) mod p == 1
        const mulRes = NodeCrypto.fieldMul(pMinus1Buf, pMinus1Buf);
        recordTest('G. Field Mul ((p - 1) * (p - 1) mod p == 1)', 'a = p - 1, b = p - 1', expAdd, mulRes.toString('hex'), mulRes.toString('hex') === expAdd);
    }

    // H. Negative / Boundary tests
    {
        // 1. Scalar = 0 rejected
        const zeroScalar = Buffer.alloc(32);
        let rejZero = !NodeCrypto.isValidScalar(zeroScalar);
        try {
            NodeCrypto.scalarMultiplyBase(zeroScalar);
            rejZero = false;
        } catch {}
        recordTest('H. Reject scalar == 0', 'scalar = 0', 'Rejected (false/throws)', rejZero ? 'Rejected' : 'Accepted', rejZero);

        // 2. Scalar = n rejected (order of curve)
        const nHex = SECP256K1_CURVE_ORDER.toString(16).padStart(64, '0');
        const nScalar = Buffer.from(nHex, 'hex');
        let rejN = !NodeCrypto.isValidScalar(nScalar);
        try {
            NodeCrypto.scalarMultiplyBase(nScalar);
            rejN = false;
        } catch {}
        recordTest('H. Reject scalar == n', 'scalar = n', 'Rejected (false/throws)', rejN ? 'Rejected' : 'Accepted', rejN);

        // 3. Scalar = p - 1 rejected as private scalar (since p - 1 > n)
        const pMinus1Hex = (SECP256K1_FIELD_PRIME - 1n).toString(16).padStart(64, '0');
        const pMinus1Scalar = Buffer.from(pMinus1Hex, 'hex');
        let rejPMinus1 = !NodeCrypto.isValidScalar(pMinus1Scalar);
        try {
            NodeCrypto.scalarMultiplyBase(pMinus1Scalar);
            rejPMinus1 = false;
        } catch {}
        recordTest('H. Reject scalar == p - 1 (since p - 1 > n)', 'scalar = p - 1', 'Rejected (false/throws)', rejPMinus1 ? 'Rejected' : 'Accepted', rejPMinus1);

        // 4. Malformed point prefix: 0x01
        const badPrefixPt = Buffer.from(pubG);
        badPrefixPt[0] = 0x01;
        const rejPrefix = !NodeCrypto.isValidPoint(badPrefixPt);
        recordTest('H. Reject point with invalid prefix 0x01', 'point prefix = 0x01', 'Rejected (false)', rejPrefix ? 'Rejected' : 'Accepted', rejPrefix);

        // 5. Point not on curve: X = 5 has no square root mod p
        const nonCurvePt = Buffer.alloc(33);
        nonCurvePt[0] = 0x02;
        nonCurvePt[32] = 0x05;
        const rejNonCurve = !NodeCrypto.isValidPoint(nonCurvePt);
        recordTest('H. Reject point not on curve (X=5 is non-quadratic residue)', 'X = 5', 'Rejected (false)', rejNonCurve ? 'Rejected' : 'Accepted', rejNonCurve);

        // 6. Wrong length scalar: 31 bytes
        const shortScalar = Buffer.alloc(31);
        const rejShortScalar = !NodeCrypto.isValidScalar(shortScalar);
        recordTest('H. Reject wrong-length scalar (31 bytes)', 'scalar len = 31', 'Rejected (false)', rejShortScalar ? 'Rejected' : 'Accepted', rejShortScalar);

        // 7. Wrong length point: 32 bytes
        const shortPoint = Buffer.alloc(32);
        const rejShortPoint = !NodeCrypto.isValidPoint(shortPoint);
        recordTest('H. Reject wrong-length point (32 bytes)', 'point len = 32', 'Rejected (false)', rejShortPoint ? 'Rejected' : 'Accepted', rejShortPoint);
    }

    console.log('\n=============================================================');
    console.log(` Stage 4 TypeScript Test Result: ${allPassed ? 'ALL PASSED' : 'FAILED'}`);
    console.log('=============================================================\n');

    return { allPassed, reports };
}
