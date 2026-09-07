import * as path from 'path';
import * as assert from 'assert';
import * as protobuf from 'protobufjs';
import { FrameParser, createFrame, MAX_FRAME_PAYLOAD_SIZE } from './network/Framing';
import { TcpClient } from './network/TcpClient';
import { runCryptoUnitTests } from './crypto/CryptoTests';
import { runBaseOtUnitTests } from './ot/BaseOtTests';
import { runCorrelatedOtUnitTests } from './ot/CorrelatedOtTests';
import { NodeCrypto } from './crypto/NodeCrypto';
import { BaseOtBob } from './ot/BaseOt';
import { CorrelatedOtBob, getLeBit, isCanonicalFieldElement } from './ot/CorrelatedOt';
import { SECP256K1_FIELD_PRIME } from './crypto/PointMath';

/**
 * Independent unit tests for the framing parser:
 * 1. Single complete frame
 * 2. Multiple concatenated frames received together
 * 3. Frame split across arbitrary chunk boundaries (1 byte at a time)
 * 4. Rejection of excessive/oversized frame lengths
 */
function runFramingUnitTests(): void {
    console.log('[Framing Tests] Running independent TCP framing unit tests...');

    // Test 1: Single complete frame
    {
        const parser = new FrameParser();
        const payload = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
        const frame = createFrame(payload);

        const extracted = parser.feed(frame);
        assert.strictEqual(extracted.length, 1);
        assert.deepStrictEqual(extracted[0], payload);
        assert.strictEqual(parser.hasPartialData(), false);
        console.log('  - Test 1 (One complete frame in single chunk): PASSED');
    }

    // Test 2: Multiple frames received together in one chunk
    {
        const parser = new FrameParser();
        const p1 = Buffer.from([0x01, 0x02]);
        const p2 = Buffer.from([0xAA, 0xBB, 0xCC]);
        const p3 = Buffer.from([0x10, 0x20, 0x30, 0x40, 0x50]);

        const f1 = createFrame(p1);
        const f2 = createFrame(p2);
        const f3 = createFrame(p3);

        const concatenated = Buffer.concat([f1, f2, f3]);
        const extracted = parser.feed(concatenated);

        assert.strictEqual(extracted.length, 3);
        assert.deepStrictEqual(extracted[0], p1);
        assert.deepStrictEqual(extracted[1], p2);
        assert.deepStrictEqual(extracted[2], p3);
        assert.strictEqual(parser.hasPartialData(), false);
        console.log('  - Test 2 (Multiple frames in single chunk): PASSED');
    }

    // Test 3: Frame split across arbitrary chunks (extreme case: 1 byte at a time)
    {
        const parser = new FrameParser();
        const payload = Buffer.from([0xCA, 0xFE, 0xBA, 0xBE, 0x42]);
        const frame = createFrame(payload);

        // Feed byte by byte
        for (let i = 0; i < frame.length; i++) {
            const chunk = frame.subarray(i, i + 1);
            const extracted = parser.feed(chunk);
            if (i < frame.length - 1) {
                assert.strictEqual(extracted.length, 0, `Premature frame extraction at byte ${i}`);
                assert.strictEqual(parser.hasPartialData(), true);
            } else {
                assert.strictEqual(extracted.length, 1);
                assert.deepStrictEqual(extracted[0], payload);
                assert.strictEqual(parser.hasPartialData(), false);
            }
        }
        console.log('  - Test 3 (Split frame fed 1 byte at a time): PASSED');
    }

    // Test 4: Rejection of excessive frame size (> 64 KB)
    {
        const parser = new FrameParser();
        const badHeader = Buffer.alloc(4);
        badHeader.writeUInt32BE(100000, 0);

        let errorCaught = false;
        try {
            parser.feed(badHeader);
        } catch (err: any) {
            errorCaught = true;
            assert.ok(err.message.includes('exceeds MAX_FRAME_PAYLOAD_SIZE'));
        }
        assert.strictEqual(errorCaught, true);
        console.log('  - Test 4 (Excessive frame size rejection): PASSED');
    }

    console.log('[Framing Tests] All framing unit tests successfully PASSED!\n');
}

enum ClientState {
    CONNECT,
    SESSION_SENT,
    COT_ROUND_1_RECEIVED,
    COT_ROUND_2_SENT,
    COT_ROUND_3_RECEIVED,
    VERIFY_REQUEST_SENT,
    COMPLETE
}

function getTestCaseY(caseNum: number): Buffer {
    const y = Buffer.alloc(32);
    switch (caseNum) {
        case 1: { // Random y in F_p
            let randY: Buffer;
            do {
                randY = NodeCrypto.generateRandom32();
            } while (!isCanonicalFieldElement(randY));
            return randY;
        }
        case 2: // y = 1
            y[31] = 1;
            return y;
        case 3: // y = 13
            y[31] = 13;
            return y;
        case 4: { // y = p - 1
            const pMinus1 = NodeCrypto.bigIntTo32Bytes(SECP256K1_FIELD_PRIME - 1n);
            return Buffer.from(pMinus1);
        }
        case 5: // y = 0
            return y;
        case 6: // y = 42
            y[31] = 42;
            return y;
        case 7: // y = 0
            return y;
        default:
            throw new Error(`Invalid test case number: ${caseNum}`);
    }
}

async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    if (args.includes('--test-only')) {
        console.log('=============================================================');
        console.log(' Cypherock COT Client - Unit Test Suite');
        console.log('=============================================================\n');

        // 1. Run independent framing unit tests
        runFramingUnitTests();

        // 2. Run independent cryptographic primitive unit tests (Stage 4)
        const cryptoRes = runCryptoUnitTests();
        if (!cryptoRes.allPassed) {
            throw new Error('Cryptographic primitive tests failed!');
        }

        // 3. Run independent Base OT unit tests (Stage 5)
        const baseOtRes = runBaseOtUnitTests();
        if (!baseOtRes.allPassed) {
            throw new Error('Base OT tests failed!');
        }

        // 4. Run independent Correlated OT / MTA unit tests (Stage 6)
        const cotOk = runCorrelatedOtUnitTests();
        if (!cotOk) {
            throw new Error('Correlated OT tests failed!');
        }

        return;
    }

    let host = '127.0.0.1';
    let port = 9000;
    let caseNum = 1;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--host' && i + 1 < args.length) {
            host = args[++i];
        } else if (args[i] === '--port' && i + 1 < args.length) {
            port = parseInt(args[++i], 10);
        } else if (args[i] === '--case' && i + 1 < args.length) {
            caseNum = parseInt(args[++i], 10);
        } else if (!args[i].startsWith('--')) {
            const parsedPort = parseInt(args[i], 10);
            if (!isNaN(parsedPort)) {
                port = parsedPort;
            }
        }
    }

    // Load shared Protobuf schema
    const protoPath = path.resolve(__dirname, '../../proto/cot.proto');
    const root = await protobuf.load(protoPath);
    const CotEnvelope = root.lookupType('cot.CotEnvelope');

    const startTime = Date.now();
    let state = ClientState.CONNECT;

    // Connect to TCP server
    const client = new TcpClient();
    await client.connect(host, port);

    // -----------------------------------------------------------------------
    // Step 1: Send SessionInit (bit_count = 256)
    // -----------------------------------------------------------------------
    const initPayload = {
        protocolVersion: 1,
        sessionInit: {
            protocolVersion: 1,
            bitCount: 256
        }
    };
    const initMsg = CotEnvelope.create(initPayload);
    await client.sendFrame(CotEnvelope.encode(initMsg).finish());
    state = ClientState.SESSION_SENT;

    // -----------------------------------------------------------------------
    // Step 2: Receive CotRound1Alice from Server (256 A_i points)
    // -----------------------------------------------------------------------
    const r1Frame = await client.receiveFrame();
    const r1Env = CotEnvelope.decode(r1Frame) as any;
    if (!r1Env.cotR1Alice || !r1Env.cotR1Alice.A || r1Env.cotR1Alice.A.length !== 256) {
        throw new Error(`Expected CotRound1Alice with 256 points, got ${r1Env.cotR1Alice?.A?.length}`);
    }
    state = ClientState.COT_ROUND_1_RECEIVED;

    // -----------------------------------------------------------------------
    // Step 3: Compute CotRound2Bob (256 B_i points) and send to Server
    // -----------------------------------------------------------------------
    const y = getTestCaseY(caseNum);
    if (!isCanonicalFieldElement(y)) {
        throw new Error('Bob term y is not a canonical field element');
    }

    const baseBobs: BaseOtBob[] = [];
    const bPoints: { data: Buffer }[] = [];

    for (let i = 0; i < 256; ++i) {
        const ptA = r1Env.cotR1Alice.A[i].data;
        if (!NodeCrypto.isValidPoint(ptA)) {
            throw new Error(`Invalid EC point A received from server at index ${i}`);
        }
        const choiceBit = getLeBit(y, i);
        const baseBob = new BaseOtBob();
        const B = baseBob.receiveAAndComputeB(ptA, choiceBit);
        baseBobs.push(baseBob);
        bPoints.push({ data: Buffer.from(B) });
    }

    const r2Payload = {
        protocolVersion: 1,
        cotR2Bob: {
            B: bPoints
        }
    };
    const r2Msg = CotEnvelope.create(r2Payload);
    await client.sendFrame(CotEnvelope.encode(r2Msg).finish());
    state = ClientState.COT_ROUND_2_SENT;

    // -----------------------------------------------------------------------
    // Step 4: Receive CotRound3Alice from Server (256 encrypted pairs)
    // -----------------------------------------------------------------------
    const r3Frame = await client.receiveFrame();
    const r3Env = CotEnvelope.decode(r3Frame) as any;
    if (!r3Env.cotR3Alice || !r3Env.cotR3Alice.pairs || r3Env.cotR3Alice.pairs.length !== 256) {
        throw new Error(`Expected CotRound3Alice with 256 pairs, got ${r3Env.cotR3Alice?.pairs?.length}`);
    }
    state = ClientState.COT_ROUND_3_RECEIVED;

    const bob = new CorrelatedOtBob();
    bob.init(y);

    for (let i = 0; i < 256; ++i) {
        const pair = r3Env.cotR3Alice.pairs[i];
        if (!pair.e0 || pair.e0.length !== 32 || !pair.e1 || pair.e1.length !== 32) {
            throw new Error(`Invalid ciphertext length received at index ${i}`);
        }
        const mc = baseBobs[i].decryptSelected(pair.e0, pair.e1);
        if (!isCanonicalFieldElement(mc)) {
            throw new Error(`Decrypted message mc at index ${i} is not a canonical field element`);
        }
        bob.recordMc(i, mc);
    }

    // Bob derives additive share V = sum(2^i * mc_i) mod p
    const V = bob.computeShareV();
    if (!V) {
        throw new Error('Failed to compute Bob additive share V');
    }

    // -----------------------------------------------------------------------
    // Step 5: Send VerificationRequest to Server (y, V)
    // -----------------------------------------------------------------------
    const reqPayload = {
        protocolVersion: 1,
        verifyReq: {
            clientTermY: y,
            clientShareV: V
        }
    };
    const reqMsg = CotEnvelope.create(reqPayload);
    await client.sendFrame(CotEnvelope.encode(reqMsg).finish());
    state = ClientState.VERIFY_REQUEST_SENT;

    // -----------------------------------------------------------------------
    // Step 6: Receive VerificationResponse from Server
    // -----------------------------------------------------------------------
    const respFrame = await client.receiveFrame();
    const respEnv = CotEnvelope.decode(respFrame) as any;
    if (!respEnv.verifyResp) {
        throw new Error('Expected VerificationResponse from server');
    }
    const verifyResp = respEnv.verifyResp;
    if (!verifyResp.success) {
        throw new Error('Server authoritative verification failed');
    }
    state = ClientState.COMPLETE;

    const serverX = Buffer.from(verifyResp.serverTermX);
    const serverU = Buffer.from(verifyResp.serverShareU);
    const productModP = Buffer.from(verifyResp.productModP);
    const sumSharesModP = Buffer.from(verifyResp.sumSharesModP);

    // Client independent verification of the received response values
    const localProduct = NodeCrypto.fieldMul(serverX, y);
    const localSum = NodeCrypto.fieldAdd(serverU, V);
    assert.strictEqual(localProduct.toString('hex'), productModP.toString('hex'), 'Product mismatch');
    assert.strictEqual(localSum.toString('hex'), sumSharesModP.toString('hex'), 'Sum mismatch');
    assert.strictEqual(localProduct.toString('hex'), localSum.toString('hex'), 'Product != Sum');

    await client.close();

    const elapsedMs = Date.now() - startTime;

    // Print final demo output matching required specification
    console.log('\n=== Cypherock COT/MTA TCP Demo ===\n');
    console.log(`Server: listening on ${host}:${port}`);
    console.log('Client: connected\n');
    console.log('Protocol version: 1');
    console.log('COT bit count: 256\n');
    console.log('Multiplicative shares:');
    console.log(`  Server x = ${serverX.toString('hex')}`);
    console.log(`  Client y = ${y.toString('hex')}\n`);
    console.log('COT:');
    console.log('  Logical OT instances: 256');
    console.log('  Bob selected messages recovered: 256\n');
    console.log('Additive shares:');
    console.log(`  Server U = ${serverU.toString('hex')}`);
    console.log(`  Client V = ${V.toString('hex')}\n`);
    console.log('Verification:');
    console.log(`  x*y mod p     = ${productModP.toString('hex')}`);
    console.log(`  (U+V) mod p   = ${sumSharesModP.toString('hex')}\n`);
    console.log('  Verification: SUCCESS');
    console.log(`  Elapsed time: ${elapsedMs} ms\n`);
}

main().catch((err) => {
    console.error('[Client Error]:', err);
    process.exit(1);
});
