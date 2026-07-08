#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "veyron/mac.hpp"

namespace veyron {

static constexpr uint16_t FRAME_MAGIC       = 0x5652;
static constexpr size_t   FRAME_HEADER_SIZE = 44;
static constexpr size_t   MAX_PAYLOAD_SIZE  = 1048576; // 1 MiB

// FLAG_MAC_PRESENT is defined in mac.hpp (included above).
static constexpr uint16_t FLAG_COMPRESSED   = 0x0002; // payload is zstd-compressed; CRC32 over compressed bytes
static constexpr uint16_t FLAG_RAW_BINARY   = 0x0010; // payload is raw bytes (PCM/Opus); skip Protobuf parse
static constexpr size_t   COMPRESS_THRESHOLD = 65536; // payloads >= this size are candidates for compression

// Wire format (all multi-byte fields big-endian):
//   [0..1]   magic   uint16  = 0x5652
//   [2..3]   flags   uint16  (FLAG_MAC_PRESENT = 0x0001)
//   [4..7]   length  uint32  = payload byte count
//   [8..39]  target  char[32] null-padded plugin_id / "kernel" / "*"
//   [40..43] crc32   uint32  = CRC-32/ISO-HDLC of payload
//   [44..]   payload
//   [44+N..] MAC tag (32 bytes) — present only when FLAG_MAC_PRESENT is set

// CRC-32/ISO-HDLC
uint32_t veyron_crc32(const uint8_t* data, size_t len);

// Build CRC-only frame (no MAC). Backward-compatible.
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::vector<uint8_t>& payload);
std::vector<uint8_t> pack_frame(const std::string& target,
                                const std::string& payload);

// Build a MAC frame: sets FLAG_MAC_PRESENT and appends 32-byte HMAC-SHA256 tag.
std::vector<uint8_t> pack_frame_mac(const std::string& target,
                                    const std::vector<uint8_t>& payload,
                                    const std::array<uint8_t, 32>& session_key);

// Result of read_frame_full.
struct FrameResult {
    std::vector<uint8_t>                    payload;
    uint16_t                                flags = 0;
    bool                                    has_mac = false;
    std::array<uint8_t, 32>                 mac = {};
    // Header the MAC tag was computed over. Equal to the wire header unless the
    // frame arrived with FLAG_COMPRESSED, in which case this is the rebuilt
    // plaintext header (flags with FLAG_COMPRESSED cleared, length/crc32 of the
    // decompressed payload) — mirroring src/ipc/framing.rs:228-241.
    std::array<uint8_t, FRAME_HEADER_SIZE>  raw_header = {};
};

// Default window the rest of a frame (after its first byte arrives) must
// complete within — bounds slow-loris stalls. See read_frame_full_with_timeout.
static constexpr int FRAME_READ_TIMEOUT_MS = 10000;

// Read one frame and return full FrameResult. Payload is always plaintext:
// if the wire frame carries FLAG_COMPRESSED, it is transparently decompressed
// (bounded to MAX_PAYLOAD_SIZE) and `flags`/`raw_header` describe the
// decompressed bytes, matching the kernel's read-side normalization.
// If session_key is non-null and FLAG_MAC_PRESENT is set, verifies the MAC tag;
// throws std::runtime_error("veyron: MAC verification failed") on mismatch.
// If session_key is null, MAC bytes are read and stored but not verified.
//
// Blocks indefinitely waiting for the first byte of the next frame (an idle
// connection must not be torn down); once a byte arrives, the remainder of
// the frame must complete within frame_timeout_ms or this throws
// std::runtime_error("veyron: frame read timed out").
FrameResult read_frame_full_with_timeout(int fd,
                                         const std::array<uint8_t, 32>* session_key,
                                         int frame_timeout_ms);

inline FrameResult read_frame_full(int fd,
                                   const std::array<uint8_t, 32>* session_key = nullptr) {
    return read_frame_full_with_timeout(fd, session_key, FRAME_READ_TIMEOUT_MS);
}

// Backward-compat: returns only payload bytes. Does NOT verify MAC.
std::vector<uint8_t> read_frame(int fd);

} // namespace veyron
