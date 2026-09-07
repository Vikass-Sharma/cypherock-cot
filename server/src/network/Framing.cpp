#include "network/Framing.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace cot::network {

std::vector<uint8_t> create_frame(const uint8_t* payload, size_t length) {
    if (length > MAX_FRAME_PAYLOAD_SIZE) {
        throw std::runtime_error("Payload exceeds MAX_FRAME_PAYLOAD_SIZE");
    }

    std::vector<uint8_t> frame(FRAME_HEADER_SIZE + length);
    uint32_t len_be = htonl(static_cast<uint32_t>(length));
    std::memcpy(frame.data(), &len_be, FRAME_HEADER_SIZE);

    if (length > 0 && payload != nullptr) {
        std::memcpy(frame.data() + FRAME_HEADER_SIZE, payload, length);
    }
    return frame;
}

void FrameParser::feed(const uint8_t* data, size_t length) {
    if (data == nullptr || length == 0) {
        return;
    }

    buffer_.insert(buffer_.end(), data, data + length);

    while (buffer_.size() >= FRAME_HEADER_SIZE) {
        uint32_t len_be = 0;
        std::memcpy(&len_be, buffer_.data(), FRAME_HEADER_SIZE);
        uint32_t frame_len = ntohl(len_be);

        if (frame_len > MAX_FRAME_PAYLOAD_SIZE) {
            buffer_.clear();
            throw std::runtime_error("Frame length exceeds MAX_FRAME_PAYLOAD_SIZE (" +
                                     std::to_string(frame_len) + " bytes)");
        }

        if (buffer_.size() >= FRAME_HEADER_SIZE + frame_len) {
            std::vector<uint8_t> frame(
                buffer_.begin() + FRAME_HEADER_SIZE,
                buffer_.begin() + FRAME_HEADER_SIZE + frame_len
            );
            complete_frames_.push_back(std::move(frame));
            buffer_.erase(buffer_.begin(), buffer_.begin() + FRAME_HEADER_SIZE + frame_len);
        } else {
            // Incomplete frame, wait for subsequent chunks
            break;
        }
    }
}

std::vector<uint8_t> FrameParser::pop_frame() {
    if (complete_frames_.empty()) {
        throw std::runtime_error("No complete frame available in FrameParser");
    }
    std::vector<uint8_t> frame = std::move(complete_frames_.front());
    complete_frames_.pop_front();
    return frame;
}

void FrameParser::reset() {
    buffer_.clear();
    complete_frames_.clear();
}

void FramedSocket::write_frame(const uint8_t* payload, size_t length) {
    std::vector<uint8_t> framed = create_frame(payload, length);
    boost::asio::write(socket_, boost::asio::buffer(framed));
}

bool FramedSocket::read_frame(std::vector<uint8_t>& out_payload, boost::system::error_code& ec) {
    uint8_t header[FRAME_HEADER_SIZE];
    boost::asio::read(socket_, boost::asio::buffer(header, FRAME_HEADER_SIZE), ec);
    if (ec) {
        return false;
    }

    uint32_t len_be = 0;
    std::memcpy(&len_be, header, FRAME_HEADER_SIZE);
    uint32_t length = ntohl(len_be);

    if (length > MAX_FRAME_PAYLOAD_SIZE) {
        ec = boost::asio::error::make_error_code(boost::asio::error::message_size);
        return false;
    }

    out_payload.resize(length);
    if (length > 0) {
        boost::asio::read(socket_, boost::asio::buffer(out_payload.data(), length), ec);
        if (ec) {
            return false;
        }
    }
    return true;
}

void FramedSocket::close() {
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

} // namespace cot::network
