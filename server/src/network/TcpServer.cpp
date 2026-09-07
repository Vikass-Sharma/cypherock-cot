#include "network/TcpServer.hpp"
#include "crypto/TrezorCrypto.hpp"
#include "ot/BaseOt.hpp"
#include "ot/CorrelatedOt.hpp"
#include "cot.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>

#include <iostream>
#include <memory>
#include <vector>
#include <cstring>
#include <chrono>

namespace cot::network {

namespace {

enum class ServerState {
    WAIT_SESSION,
    COT_ROUND_1_SENT,
    COT_ROUND_2_RECEIVED,
    COT_ROUND_3_SENT,
    VERIFY_REQUEST_RECEIVED,
    COMPLETE
};

} // namespace

bool get_test_case_x(int case_num, uint8_t x_out[32]) {
    std::memset(x_out, 0, 32);
    switch (case_num) {
        case 1: // Random x in F_p
            do {
                crypto::generate_random_32(x_out);
            } while (!ot::is_canonical_field_element(x_out));
            return true;
        case 2: // x = 1
            x_out[31] = 1;
            return true;
        case 3: // x = 5
            x_out[31] = 5;
            return true;
        case 4: // x = p - 1
            std::memcpy(x_out, crypto::SECP256K1_FIELD_PRIME_BE.data(), 32);
            x_out[31] -= 1;
            return true;
        case 5: // x = 0
            return true;
        case 6: // x = 0
            return true;
        case 7: // x = 42
            x_out[31] = 42;
            return true;
        default:
            return false;
    }
}

TcpServer::TcpServer(boost::asio::io_context& io_ctx, const std::string& host, uint16_t port)
    : io_ctx_(io_ctx)
    , host_(host)
    , port_(port)
    , acceptor_(io_ctx)
{
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(host_), port_);
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen(1);

    // If port 0 was passed, query the actual assigned OS port
    port_ = acceptor_.local_endpoint().port();
}

bool TcpServer::run_cot_session(int case_num) {
    uint8_t x[32];
    if (!get_test_case_x(case_num, x)) {
        std::cerr << "[Server Error] Invalid test case number: " << case_num << "\n";
        return false;
    }

    std::cout << "[Server] Listening on " << host_ << ":" << port_ << " ...\n";

    boost::asio::ip::tcp::socket socket(io_ctx_);
    boost::system::error_code ec;
    acceptor_.accept(socket, ec);
    if (ec) {
        std::cerr << "[Server Error] Failed to accept client connection: " << ec.message() << "\n";
        return false;
    }

    std::string client_endpoint = socket.remote_endpoint().address().to_string() + ":" +
                                  std::to_string(socket.remote_endpoint().port());
    std::cout << "[Server] Client connected: " << client_endpoint << "\n";

    FramedSocket framed_sock(std::move(socket));
    ServerState state = ServerState::WAIT_SESSION;

    auto start_time = std::chrono::steady_clock::now();

    // Allocate envelopes on the heap to avoid large stack buffers
    auto in_env = std::make_unique<cot_CotEnvelope>();
    auto out_env = std::make_unique<cot_CotEnvelope>();
    std::vector<uint8_t> payload;
    std::vector<uint8_t> out_buf(MAX_FRAME_PAYLOAD_SIZE);

    // Alice COT context
    ot::CorrelatedOtAlice alice;
    if (!alice.init(x, /*deterministic=*/false)) {
        std::cerr << "[Server Error] Alice COT init failed for term x\n";
        framed_sock.close();
        return false;
    }

    std::vector<ot::BaseOtAlice> base_alices(256);
    uint8_t U[32] = {0};
    uint8_t y[32] = {0};
    uint8_t V[32] = {0};
    uint8_t product[32] = {0};
    uint8_t sum[32] = {0};
    bool verification_passed = false;

    // -----------------------------------------------------------------------
    // Step 1: WAIT_SESSION -> Read SessionInit from client
    // -----------------------------------------------------------------------
    if (!framed_sock.read_frame(payload, ec)) {
        std::cerr << "[Server Error] Failed to read SessionInit frame: " << ec.message() << "\n";
        framed_sock.close();
        return false;
    }

    *in_env = cot_CotEnvelope_init_default;
    pb_istream_t in_stream = pb_istream_from_buffer(payload.data(), payload.size());
    if (!pb_decode(&in_stream, cot_CotEnvelope_fields, in_env.get())) {
        std::cerr << "[Server Error] Failed to decode SessionInit: " << PB_GET_ERROR(&in_stream) << "\n";
        framed_sock.close();
        return false;
    }

    if (in_env->protocol_version != 1 || in_env->which_payload != cot_CotEnvelope_session_init_tag) {
        std::cerr << "[Server Error] Unexpected envelope payload in WAIT_SESSION state (tag="
                  << in_env->which_payload << ")\n";
        framed_sock.close();
        return false;
    }

    if (in_env->payload.session_init.protocol_version != 1 ||
        in_env->payload.session_init.bit_count != 256) {
        std::cerr << "[Server Error] Invalid SessionInit parameters: protocol_version="
                  << in_env->payload.session_init.protocol_version
                  << ", bit_count=" << in_env->payload.session_init.bit_count << "\n";
        framed_sock.close();
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 2: COT_ROUND_1_SENT -> Alice generates 256 A_i points and sends CotRound1Alice
    // -----------------------------------------------------------------------
    *out_env = cot_CotEnvelope_init_default;
    out_env->protocol_version = 1;
    out_env->which_payload = cot_CotEnvelope_cot_r1_alice_tag;
    out_env->payload.cot_r1_alice.A_count = 256;

    for (size_t i = 0; i < 256; ++i) {
        if (!base_alices[i].init()) {
            std::cerr << "[Server Error] Failed to initialize BaseOtAlice instance at index " << i << "\n";
            framed_sock.close();
            return false;
        }
        std::memcpy(out_env->payload.cot_r1_alice.A[i].data, base_alices[i].get_A(), 33);
    }

    pb_ostream_t out_stream = pb_ostream_from_buffer(out_buf.data(), out_buf.size());
    if (!pb_encode(&out_stream, cot_CotEnvelope_fields, out_env.get())) {
        std::cerr << "[Server Error] Failed to encode CotRound1Alice: " << PB_GET_ERROR(&out_stream) << "\n";
        framed_sock.close();
        return false;
    }

    framed_sock.write_frame(out_buf.data(), out_stream.bytes_written);
    state = ServerState::COT_ROUND_1_SENT;

    // -----------------------------------------------------------------------
    // Step 3: COT_ROUND_2_RECEIVED -> Read CotRound2Bob from client
    // -----------------------------------------------------------------------
    if (!framed_sock.read_frame(payload, ec)) {
        std::cerr << "[Server Error] Failed to read CotRound2Bob frame: " << ec.message() << "\n";
        framed_sock.close();
        return false;
    }

    *in_env = cot_CotEnvelope_init_default;
    in_stream = pb_istream_from_buffer(payload.data(), payload.size());
    if (!pb_decode(&in_stream, cot_CotEnvelope_fields, in_env.get())) {
        std::cerr << "[Server Error] Failed to decode CotRound2Bob: " << PB_GET_ERROR(&in_stream) << "\n";
        framed_sock.close();
        return false;
    }

    if (in_env->which_payload != cot_CotEnvelope_cot_r2_bob_tag) {
        std::cerr << "[Server Error] Protocol state error: expected CotRound2Bob, got tag "
                  << in_env->which_payload << "\n";
        framed_sock.close();
        return false;
    }

    if (in_env->payload.cot_r2_bob.B_count != 256) {
        std::cerr << "[Server Error] Array count mismatch: expected 256 B points, got "
                  << in_env->payload.cot_r2_bob.B_count << "\n";
        framed_sock.close();
        return false;
    }

    state = ServerState::COT_ROUND_2_RECEIVED;

    // Alice processes B_i points, derives k0_i, k1_i, encrypts m0_i, m1_i
    *out_env = cot_CotEnvelope_init_default;
    out_env->protocol_version = 1;
    out_env->which_payload = cot_CotEnvelope_cot_r3_alice_tag;
    out_env->payload.cot_r3_alice.pairs_count = 256;

    for (size_t i = 0; i < 256; ++i) {
        const uint8_t* B_i = in_env->payload.cot_r2_bob.B[i].data;
        if (!crypto::is_valid_point(B_i)) {
            std::cerr << "[Server Error] Received invalid EC point B at index " << i << "\n";
            framed_sock.close();
            return false;
        }

        if (!base_alices[i].receive_B(B_i)) {
            std::cerr << "[Server Error] BaseOtAlice receive_B failed at index " << i << "\n";
            framed_sock.close();
            return false;
        }

        uint8_t e0[32], e1[32];
        if (!base_alices[i].encrypt_messages(alice.get_m0(i), alice.get_m1(i), e0, e1)) {
            std::cerr << "[Server Error] BaseOtAlice encryption failed at index " << i << "\n";
            framed_sock.close();
            return false;
        }

        std::memcpy(out_env->payload.cot_r3_alice.pairs[i].e0, e0, 32);
        std::memcpy(out_env->payload.cot_r3_alice.pairs[i].e1, e1, 32);
    }

    // Compute Alice's additive share U
    if (!alice.compute_share_U(U)) {
        std::cerr << "[Server Error] Failed to compute additive share U\n";
        framed_sock.close();
        return false;
    }

    // Send CotRound3Alice to client
    out_stream = pb_ostream_from_buffer(out_buf.data(), out_buf.size());
    if (!pb_encode(&out_stream, cot_CotEnvelope_fields, out_env.get())) {
        std::cerr << "[Server Error] Failed to encode CotRound3Alice: " << PB_GET_ERROR(&out_stream) << "\n";
        framed_sock.close();
        return false;
    }

    framed_sock.write_frame(out_buf.data(), out_stream.bytes_written);
    state = ServerState::COT_ROUND_3_SENT;

    // -----------------------------------------------------------------------
    // Step 4: VERIFY_REQUEST_RECEIVED -> Read VerificationRequest from client
    // -----------------------------------------------------------------------
    if (!framed_sock.read_frame(payload, ec)) {
        std::cerr << "[Server Error] Failed to read VerificationRequest frame: " << ec.message() << "\n";
        framed_sock.close();
        return false;
    }

    *in_env = cot_CotEnvelope_init_default;
    in_stream = pb_istream_from_buffer(payload.data(), payload.size());
    if (!pb_decode(&in_stream, cot_CotEnvelope_fields, in_env.get())) {
        std::cerr << "[Server Error] Failed to decode VerificationRequest: " << PB_GET_ERROR(&in_stream) << "\n";
        framed_sock.close();
        return false;
    }

    if (in_env->which_payload != cot_CotEnvelope_verify_req_tag) {
        std::cerr << "[Server Error] Protocol state error: expected VerificationRequest, got tag "
                  << in_env->which_payload << "\n";
        framed_sock.close();
        return false;
    }

    std::memcpy(y, in_env->payload.verify_req.client_term_y, 32);
    std::memcpy(V, in_env->payload.verify_req.client_share_v, 32);

    if (!ot::is_canonical_field_element(y)) {
        std::cerr << "[Server Error] Received non-canonical field element y from client\n";
        framed_sock.close();
        return false;
    }
    if (!ot::is_canonical_field_element(V)) {
        std::cerr << "[Server Error] Received non-canonical additive share V from client\n";
        framed_sock.close();
        return false;
    }

    state = ServerState::VERIFY_REQUEST_RECEIVED;

    // Server authoritative independent verification:
    // product = (x * y) mod p
    // sum = (U + V) mod p
    crypto::field_mul(x, y, product);
    crypto::field_add(U, V, sum);
    verification_passed = (std::memcmp(product, sum, 32) == 0);

    // Send VerificationResponse
    *out_env = cot_CotEnvelope_init_default;
    out_env->protocol_version = 1;
    out_env->which_payload = cot_CotEnvelope_verify_resp_tag;
    out_env->payload.verify_resp.success = verification_passed;
    std::memcpy(out_env->payload.verify_resp.server_term_x, x, 32);
    std::memcpy(out_env->payload.verify_resp.server_share_u, U, 32);
    std::memcpy(out_env->payload.verify_resp.product_mod_p, product, 32);
    std::memcpy(out_env->payload.verify_resp.sum_shares_mod_p, sum, 32);

    out_stream = pb_ostream_from_buffer(out_buf.data(), out_buf.size());
    if (!pb_encode(&out_stream, cot_CotEnvelope_fields, out_env.get())) {
        std::cerr << "[Server Error] Failed to encode VerificationResponse: " << PB_GET_ERROR(&out_stream) << "\n";
        framed_sock.close();
        return false;
    }

    framed_sock.write_frame(out_buf.data(), out_stream.bytes_written);
    state = ServerState::COMPLETE;
    framed_sock.close();

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Print final demo output
    std::cout << "\n=== Cypherock COT/MTA TCP Demo ===\n\n";
    std::cout << "Server: listening on " << host_ << ":" << port_ << "\n";
    std::cout << "Client: connected (" << client_endpoint << ")\n\n";
    std::cout << "Protocol version: 1\n";
    std::cout << "COT bit count: 256\n\n";
    std::cout << "Multiplicative shares:\n";
    std::cout << "  Server x = " << crypto::to_hex(x, 32) << "\n";
    std::cout << "  Client y = " << crypto::to_hex(y, 32) << "\n\n";
    std::cout << "COT:\n";
    std::cout << "  Logical OT instances: 256\n";
    std::cout << "  Bob selected messages recovered: 256\n\n";
    std::cout << "Additive shares:\n";
    std::cout << "  Server U = " << crypto::to_hex(U, 32) << "\n";
    std::cout << "  Client V = " << crypto::to_hex(V, 32) << "\n\n";
    std::cout << "Verification:\n";
    std::cout << "  x*y mod p     = " << crypto::to_hex(product, 32) << "\n";
    std::cout << "  (U+V) mod p   = " << crypto::to_hex(sum, 32) << "\n\n";
    std::cout << "  Verification: " << (verification_passed ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "  Elapsed time: " << elapsed_ms << " ms\n\n";

    return verification_passed;
}

bool TcpServer::run_single_handshake_session() {
    return run_cot_session(1);
}

} // namespace cot::network
