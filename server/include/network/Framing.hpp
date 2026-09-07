#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <deque>
#include <stdexcept>
#include <boost/asio.hpp>

namespace cot::network {

// Maximum allowed payload size for a single protobuf frame (64 KB)
// Protects against excessive allocation attacks while easily fitting full 256-bit COT messages.
constexpr size_t MAX_FRAME_PAYLOAD_SIZE = 64 * 1024;
constexpr size_t FRAME_HEADER_SIZE = 4;

// Serializes a payload into a framed buffer: [4-byte big-endian length][payload]
std::vector<uint8_t> create_frame(const uint8_t* payload, size_t length);

// Stream parser that accumulates arbitrary chunks of received bytes and extracts complete frames.
// Completely immune to TCP fragmentation (split frames) and concatenation (multiple frames in one chunk).
class FrameParser {
public:
    FrameParser() = default;

    // Feed a chunk of received bytes into the parser buffer
    void feed(const uint8_t* data, size_t length);

    // Checks if at least one complete frame is ready
    bool has_frame() const { return !complete_frames_.empty(); }

    // Pops the next complete frame payload
    std::vector<uint8_t> pop_frame();

    // Returns count of pending ready frames
    size_t ready_count() const { return complete_frames_.size(); }

    // Clears parser state
    void reset();

private:
    std::vector<uint8_t> buffer_;
    std::deque<std::vector<uint8_t>> complete_frames_;
};

// High-level wrapper over boost::asio::ip::tcp::socket providing framed communication
class FramedSocket {
public:
    explicit FramedSocket(boost::asio::ip::tcp::socket socket)
        : socket_(std::move(socket)) {}

    boost::asio::ip::tcp::socket& socket() { return socket_; }

    // Sends a payload with 4-byte big-endian length prefix
    void write_frame(const uint8_t* payload, size_t length);

    // Reads exactly one complete framed payload (reads 4-byte length, then exact payload bytes)
    // Returns false on clean EOF / disconnect
    bool read_frame(std::vector<uint8_t>& out_payload, boost::system::error_code& ec);

    // Closes socket cleanly
    void close();

private:
    boost::asio::ip::tcp::socket socket_;
};

} // namespace cot::network
