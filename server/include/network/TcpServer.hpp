#pragma once

#include <string>
#include <cstdint>
#include <boost/asio.hpp>
#include "network/Framing.hpp"

namespace cot::network {

class TcpServer {
public:
    TcpServer(boost::asio::io_context& io_ctx, const std::string& host, uint16_t port);

    uint16_t port() const { return port_; }
    std::string host() const { return host_; }

    // Performs the complete Stage 7 batched COT / MTA protocol session over TCP
    // case_num: 1=random, 2=1x1, 3=5x13, 4=(p-1)x(p-1), 5=0x0, 6=0x42, 7=42x0
    bool run_cot_session(int case_num = 1);

    // Backward compatibility with Stage 3 smoke test
    bool run_single_handshake_session();

private:
    boost::asio::io_context& io_ctx_;
    std::string host_;
    uint16_t port_;
    boost::asio::ip::tcp::acceptor acceptor_;
};

// Helper to get x for test cases 1..7
bool get_test_case_x(int case_num, uint8_t x_out[32]);

} // namespace cot::network
