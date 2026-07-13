#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "veyron/framing.hpp"
#include "veyron/mac.hpp"
#include "veyron_protocol.pb.h"

namespace veyron {

// Mirrors the kernel's inbound reassembly bounds (see src/ipc/connection.rs)
// and the rust/python SDKs' client-side reassembly (T-18).
static constexpr size_t MAX_REASSEMBLY_STREAMS = 64;
static constexpr std::chrono::seconds REASSEMBLY_TIMEOUT{30};

class VeyronClient {
public:
    // secret: shared JWT secret for MAC key derivation.
    // Pass empty vector (default) to skip MAC — only valid with allow_no_auth:true kernels.
    explicit VeyronClient(std::string socket_path,
                          std::vector<uint8_t> secret = {});
    // Adopt an already-connected fd directly (tests, or a socket established
    // outside connect()). VeyronClient owns fd and closes it on destruction.
    explicit VeyronClient(int fd, std::vector<uint8_t> secret = {});
    ~VeyronClient();

    void    connect();
    void    close();

    // Send PluginRegister, return the RegisterAck envelope.
    // Derives session_key_ from ack.session_nonce when secret is set.
    Envelope register_plugin(const std::string& plugin_id,
                             const std::string& jwt_token = "");

    // Same, declaring a manifest (permissions/actions/events/ipc_targets) —
    // required for IPC send permission and kernel-brokered action routing
    // (PluginManifest.actions), neither of which work with an empty manifest.
    Envelope register_plugin(const std::string& plugin_id,
                             const PluginManifest& manifest,
                             const std::string& jwt_token = "");

    void    send(const std::string& target, const Envelope& env);
    Envelope recv();

    // Split `payload` into FLAG_FRAGMENTED frames of at most `chunk_size` data
    // bytes each and send them on a fresh stream id. The receiving side (kernel
    // or another VeyronClient) reassembles them into one logical frame. Bounds
    // mirror the kernel: total payload <= 1 MiB, <= 65535 fragments.
    void send_fragmented(const std::string& target,
                        const std::vector<uint8_t>& payload,
                        size_t chunk_size);

    // Receive the next complete frame, transparently reassembling
    // FLAG_FRAGMENTED frames. Mirrors the rust/python SDKs' recv_frame.
    FrameResult recv_frame();

    void   subscribe(const std::vector<std::string>& event_types);
    // Confirms an Event was received and handled — kernel stops retrying it.
    // An un-acked event is redelivered up to max_retries then dropped (T-06).
    void   ack_event(const std::string& event_id);
    double ping();

    // Publish an event to the kernel event bus. Requires PERMISSION_EVENT_PUBLISH.
    // timeout_ms == 0 uses the kernel default of 30s. Throws std::runtime_error
    // on a kernel Error envelope or on timeout. The returned EventPublishAck is
    // returned as-is regardless of its status field (OK/ERROR/PERMISSION_DENY) —
    // callers inspect ack.status() themselves, mirroring the Rust SDK.
    EventPublishAck publish_event(const std::string& event_type,
                                  const std::vector<uint8_t>& payload_json,
                                  uint32_t timeout_ms = 0);

private:
    std::string                            socket_path_;
    int                                    fd_ = -1;
    std::string                            plugin_id_;
    std::vector<uint8_t>                   secret_;
    std::optional<std::array<uint8_t,32>>  session_key_;

    // In-flight fragment reassembly, keyed by stream_id. Mirrors the rust
    // SDK's ReassemblyBuf / client.rs absorb_fragment (T-18).
    struct ReassemblyBuf {
        std::unordered_map<uint16_t, std::vector<uint8_t>> fragments;
        uint16_t total = 0;
        uint16_t flags = 0;
        std::chrono::steady_clock::time_point first_seen;
        size_t buffered_bytes = 0;

        ReassemblyBuf(uint16_t total_, uint16_t flags_)
            : total(total_), flags(flags_), first_seen(std::chrono::steady_clock::now()) {}

        bool is_complete() const { return fragments.size() == total; }
        std::vector<uint8_t> reassemble() const {
            std::vector<uint8_t> out;
            out.reserve(buffered_bytes);
            for (uint16_t seq = 0; seq < total; ++seq) {
                const auto& chunk = fragments.at(seq);
                out.insert(out.end(), chunk.begin(), chunk.end());
            }
            return out;
        }
    };
    std::unordered_map<uint32_t, ReassemblyBuf> reassembly_;
    uint32_t next_stream_id_ = 1;

    // Buffer one fragment; returns the reassembled frame when the set is
    // complete. Throws on protocol/bound violations (mirrors absorb_fragment
    // in the rust/python SDKs).
    std::optional<FrameResult> absorb_fragment(FrameResult frame);

    void write_all(const std::vector<uint8_t>& frame);

    // Send without MAC regardless of session_key_ (used for registration handshake).
    void send_envelope_no_mac(const std::string& target, const Envelope& env);
    // Send with MAC when session_key_ is set, else CRC-only.
    void send_envelope(const std::string& target, const Envelope& env);

    // Like recv_frame(), but bounds the total wait (including the first byte)
    // by deadline instead of the per-frame idle-forever default.
    FrameResult recv_frame_with_deadline(std::chrono::steady_clock::time_point deadline);
};

} // namespace veyron
