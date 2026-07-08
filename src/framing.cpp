#include "veyron/framing.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zstd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace veyron {

// ---------------------------------------------------------------------------
// CRC-32/ISO-HDLC
// ---------------------------------------------------------------------------
static std::array<uint32_t, 256> build_crc32_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[i] = c;
    }
    return t;
}

uint32_t veyron_crc32(const uint8_t* data, size_t len) {
    static const auto table = build_crc32_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// pack_frame (CRC-only, backward-compatible)
// ---------------------------------------------------------------------------
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::vector<uint8_t>& payload) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: payload exceeds 1 MiB limit");

    uint32_t crc = veyron_crc32(payload.data(), payload.size());

    uint8_t header[FRAME_HEADER_SIZE] = {};
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    // flags = 0 (no MAC)
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(header + 4, &len_be, 4);
    const size_t copy_len = std::min(target.size(), size_t{32});
    std::memcpy(header + 8, target.data(), copy_len);
    const uint32_t crc_be = htonl(crc);
    std::memcpy(header + 40, &crc_be, 4);

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size());
    frame.insert(frame.end(), header, header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::string& payload) {
    return pack_frame(target, std::vector<uint8_t>(payload.begin(), payload.end()));
}

// ---------------------------------------------------------------------------
// pack_frame_mac — sets FLAG_MAC_PRESENT and appends 32-byte HMAC tag
// ---------------------------------------------------------------------------
std::vector<uint8_t> pack_frame_mac(const std::string& target,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>& session_key) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: payload exceeds 1 MiB limit");

    uint32_t crc = veyron_crc32(payload.data(), payload.size());

    uint8_t header[FRAME_HEADER_SIZE] = {};
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(header + 0, &magic_be, 2);
    const uint16_t flags_be = htons(FLAG_MAC_PRESENT);
    std::memcpy(header + 2, &flags_be, 2);
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(header + 4, &len_be, 4);
    const size_t copy_len = std::min(target.size(), size_t{32});
    std::memcpy(header + 8, target.data(), copy_len);
    const uint32_t crc_be = htonl(crc);
    std::memcpy(header + 40, &crc_be, 4);

    auto tag = compute_tag(session_key,
                           header, FRAME_HEADER_SIZE,
                           payload.data(), payload.size());

    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size() + MAC_TAG_LEN);
    frame.insert(frame.end(), header, header + FRAME_HEADER_SIZE);
    frame.insert(frame.end(), payload.begin(), payload.end());
    frame.insert(frame.end(), tag.begin(), tag.end());
    return frame;
}

// ---------------------------------------------------------------------------
// Internal I/O helpers
// ---------------------------------------------------------------------------
static void recv_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        const ssize_t r = ::read(fd, buf + total, n - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            throw std::runtime_error("veyron: connection closed or recv error");
        total += static_cast<size_t>(r);
    }
}

using Deadline = std::chrono::steady_clock::time_point;

static void recv_exact_deadline(int fd, uint8_t* buf, size_t n, Deadline deadline) {
    size_t total = 0;
    while (total < n) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            throw std::runtime_error("veyron: frame read timed out");
        const auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, static_cast<int>(remaining_ms));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            throw std::runtime_error("veyron: poll failed during frame read");
        }
        if (pr == 0)
            throw std::runtime_error("veyron: frame read timed out");

        const ssize_t r = ::read(fd, buf + total, n - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            throw std::runtime_error("veyron: connection closed or recv error");
        total += static_cast<size_t>(r);
    }
}

// Bounded zstd decompression mirroring src/ipc/framing.rs:234.
static std::vector<uint8_t> zstd_decompress_bounded(const uint8_t* data, size_t len) {
    unsigned long long content_size = ZSTD_getFrameContentSize(data, len);
    if (content_size == ZSTD_CONTENTSIZE_ERROR)
        throw std::runtime_error("veyron: decompress frame: invalid zstd frame");
    if (content_size == ZSTD_CONTENTSIZE_UNKNOWN || content_size > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: decompress frame: content size unknown or too large");

    std::vector<uint8_t> out(static_cast<size_t>(content_size));
    size_t result = ZSTD_decompress(out.data(), out.size(), data, len);
    if (ZSTD_isError(result) || result != out.size())
        throw std::runtime_error(std::string("veyron: decompress frame: ") + ZSTD_getErrorName(result));
    return out;
}

// Rebuilds the 44-byte header exactly as serialize_header (src/ipc/framing.rs)
// does, for the given flags/target/payload.
static void build_header(uint8_t out[FRAME_HEADER_SIZE], uint16_t flags,
                         const uint8_t target[32], const std::vector<uint8_t>& payload) {
    std::memset(out, 0, FRAME_HEADER_SIZE);
    const uint16_t magic_be = htons(FRAME_MAGIC);
    std::memcpy(out + 0, &magic_be, 2);
    const uint16_t flags_be = htons(flags);
    std::memcpy(out + 2, &flags_be, 2);
    const uint32_t len_be = htonl(static_cast<uint32_t>(payload.size()));
    std::memcpy(out + 4, &len_be, 4);
    std::memcpy(out + 8, target, 32);
    const uint32_t crc_be = htonl(veyron_crc32(payload.data(), payload.size()));
    std::memcpy(out + 40, &crc_be, 4);
}

// ---------------------------------------------------------------------------
// read_frame_full_with_timeout
// ---------------------------------------------------------------------------
FrameResult read_frame_full_with_timeout(int fd, const std::array<uint8_t, 32>* session_key,
                                         int frame_timeout_ms) {
    uint8_t header[FRAME_HEADER_SIZE];
    // Block indefinitely for the first byte of the next frame — an idle
    // connection between frames must not be torn down. Once a byte arrives,
    // a frame is in progress and the remainder is bounded by frame_timeout_ms.
    recv_exact(fd, header, 1);
    const Deadline deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(frame_timeout_ms);
    recv_exact_deadline(fd, header + 1, FRAME_HEADER_SIZE - 1, deadline);

    uint16_t magic;
    std::memcpy(&magic, header + 0, 2);
    if (ntohs(magic) != FRAME_MAGIC)
        throw std::runtime_error("veyron: invalid frame magic");

    uint16_t flags;
    std::memcpy(&flags, header + 2, 2);
    flags = ntohs(flags);

    uint32_t length;
    std::memcpy(&length, header + 4, 4);
    length = ntohl(length);
    if (length > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: frame payload exceeds 1 MiB limit");

    uint32_t expected_crc;
    std::memcpy(&expected_crc, header + 40, 4);
    expected_crc = ntohl(expected_crc);

    std::vector<uint8_t> payload(length);
    if (length > 0)
        recv_exact_deadline(fd, payload.data(), length, deadline);

    // CRC is over the wire bytes (possibly compressed); verify before decompressing.
    if (veyron_crc32(payload.data(), payload.size()) != expected_crc)
        throw std::runtime_error("veyron: CRC32 mismatch");

    // Normalize the in-memory invariant: payload is always plaintext, and the
    // header used for MAC verification describes the plaintext — mirroring
    // src/ipc/framing.rs:228-241.
    std::array<uint8_t, FRAME_HEADER_SIZE> effective_header;
    std::memcpy(effective_header.data(), header, FRAME_HEADER_SIZE);
    if (flags & FLAG_COMPRESSED) {
        payload = zstd_decompress_bounded(payload.data(), payload.size());
        flags &= static_cast<uint16_t>(~FLAG_COMPRESSED);
        build_header(effective_header.data(), flags, header + 8, payload);
    }

    FrameResult result;
    result.flags = flags;
    result.raw_header = effective_header;
    result.payload = std::move(payload);

    if (flags & FLAG_MAC_PRESENT) {
        recv_exact_deadline(fd, result.mac.data(), MAC_TAG_LEN, deadline);
        result.has_mac = true;
        if (session_key != nullptr) {
            if (!verify_tag(*session_key,
                            effective_header.data(), FRAME_HEADER_SIZE,
                            result.payload.data(), result.payload.size(),
                            result.mac.data(), MAC_TAG_LEN))
                throw std::runtime_error("veyron: MAC verification failed");
        }
    } else if (session_key != nullptr) {
        throw std::runtime_error("veyron: MAC missing on secured connection");
    }

    return result;
}

// ---------------------------------------------------------------------------
// read_frame (backward-compat — no MAC verification)
// ---------------------------------------------------------------------------
std::vector<uint8_t> read_frame(int fd) {
    return read_frame_full(fd, nullptr).payload;
}

} // namespace veyron
