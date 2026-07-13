#include "veyron/client.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace veyron {

VeyronClient::VeyronClient(std::string socket_path, std::vector<uint8_t> secret)
    : socket_path_(std::move(socket_path))
    , secret_(std::move(secret)) {}

VeyronClient::VeyronClient(int fd, std::vector<uint8_t> secret)
    : fd_(fd)
    , secret_(std::move(secret)) {}

VeyronClient::~VeyronClient() { close(); }

void VeyronClient::connect() {
    close();
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0)
        throw std::runtime_error("veyron: socket() failed");

    if (socket_path_.size() >= sizeof(sockaddr_un{}.sun_path)) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("veyron: socket path too long: " + socket_path_);
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("veyron: connect() failed: " + socket_path_);
    }
}

void VeyronClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

Envelope VeyronClient::register_plugin(const std::string& plugin_id,
                                        const std::string& jwt_token) {
    return register_plugin(plugin_id, PluginManifest{}, jwt_token);
}

Envelope VeyronClient::register_plugin(const std::string& plugin_id,
                                        const PluginManifest& manifest,
                                        const std::string& jwt_token) {
    plugin_id_ = plugin_id;

    Envelope env;
    auto* reg = env.mutable_plugin_register();
    reg->set_plugin_id(plugin_id);
    reg->set_jwt_token(jwt_token);
    *reg->mutable_manifest() = manifest;

    // Registration frame is always CRC-only; session_key not yet derived.
    send_envelope_no_mac("kernel", env);
    Envelope ack = recv();

    if (ack.has_plugin_register_ack() && !secret_.empty()) {
        const auto& nonce_str = ack.plugin_register_ack().session_nonce();
        if (!nonce_str.empty()) {
            std::vector<uint8_t> nonce(nonce_str.begin(), nonce_str.end());
            session_key_ = derive_session_key(secret_, nonce, plugin_id);
        }
    }

    return ack;
}

void VeyronClient::send(const std::string& target, const Envelope& env) {
    send_envelope(target, env);
}

std::optional<FrameResult> VeyronClient::absorb_fragment(FrameResult frame) {
    // Prune stale sets first so an abandoned stream cannot pin memory.
    const auto now = std::chrono::steady_clock::now();
    for (auto it = reassembly_.begin(); it != reassembly_.end();) {
        if (now - it->second.first_seen >= REASSEMBLY_TIMEOUT)
            it = reassembly_.erase(it);
        else
            ++it;
    }

    auto hdr = parse_frag_header(frame.payload.data(), frame.payload.size());
    if (!hdr)
        throw std::runtime_error("veyron: fragment header too short");
    if (hdr->total == 0 || hdr->sequence >= hdr->total)
        throw std::runtime_error("veyron: invalid fragment header");

    auto it = reassembly_.find(hdr->stream_id);
    if (it != reassembly_.end()) {
        if (it->second.total != hdr->total) {
            reassembly_.erase(it);
            throw std::runtime_error("veyron: fragment total mismatch within stream");
        }
    } else if (reassembly_.size() >= MAX_REASSEMBLY_STREAMS) {
        throw std::runtime_error("veyron: too many concurrent fragment streams");
    }

    auto emplaced = reassembly_.try_emplace(
        hdr->stream_id, hdr->total,
        static_cast<uint16_t>(frame.flags & ~(FLAG_FRAGMENTED | FLAG_MAC_PRESENT)));
    ReassemblyBuf& buf = emplaced.first->second;

    std::vector<uint8_t> chunk(frame.payload.begin() + FRAG_HEADER_SIZE, frame.payload.end());
    // A re-sent sequence replaces its old bytes; subtracting first keeps the
    // arithmetic underflow-free, matching the rust/python SDKs' accounting.
    size_t replaced_len = 0;
    auto fit = buf.fragments.find(hdr->sequence);
    if (fit != buf.fragments.end())
        replaced_len = fit->second.size();
    const size_t new_total = buf.buffered_bytes - replaced_len + chunk.size();
    if (new_total > MAX_PAYLOAD_SIZE) {
        reassembly_.erase(hdr->stream_id);
        throw std::runtime_error("veyron: reassembled payload too large");
    }
    buf.buffered_bytes = new_total;
    buf.fragments[hdr->sequence] = std::move(chunk);

    if (buf.is_complete()) {
        FrameResult result;
        result.flags = buf.flags;
        result.payload = buf.reassemble();
        reassembly_.erase(hdr->stream_id);
        return result;
    }
    return std::nullopt;
}

FrameResult VeyronClient::recv_frame() {
    const std::array<uint8_t,32>* key_ptr =
        session_key_.has_value() ? &session_key_.value() : nullptr;
    while (true) {
        auto frame = read_frame_full(fd_, key_ptr);
        if (frame.flags & FLAG_FRAGMENTED) {
            auto complete = absorb_fragment(std::move(frame));
            if (!complete)
                continue;
            return std::move(*complete);
        }
        return frame;
    }
}

FrameResult VeyronClient::recv_frame_with_deadline(std::chrono::steady_clock::time_point deadline) {
    const std::array<uint8_t,32>* key_ptr =
        session_key_.has_value() ? &session_key_.value() : nullptr;
    while (true) {
        auto frame = read_frame_full_with_deadline(fd_, key_ptr, deadline);
        if (frame.flags & FLAG_FRAGMENTED) {
            auto complete = absorb_fragment(std::move(frame));
            if (!complete)
                continue;
            return std::move(*complete);
        }
        return frame;
    }
}

Envelope VeyronClient::recv() {
    auto result = recv_frame();
    Envelope env;
    if (!env.ParseFromArray(result.payload.data(),
                            static_cast<int>(result.payload.size())))
        throw std::runtime_error("veyron: protobuf parse failed");
    return env;
}

void VeyronClient::send_fragmented(const std::string& target,
                                   const std::vector<uint8_t>& payload,
                                   size_t chunk_size) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: payload exceeds 1 MiB limit");
    if (chunk_size == 0 || chunk_size + FRAG_HEADER_SIZE > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("veyron: invalid fragment chunk_size");

    size_t total = payload.empty() ? 1 : (payload.size() + chunk_size - 1) / chunk_size;
    if (total > 0xFFFF)
        throw std::runtime_error("veyron: payload needs too many fragments");

    const uint32_t stream_id = next_stream_id_;
    next_stream_id_ = next_stream_id_ + 1;
    if (next_stream_id_ == 0)
        next_stream_id_ = 1;
    const uint16_t fragment_id = static_cast<uint16_t>(stream_id & 0xFFFF);

    for (size_t seq = 0; seq < total; ++seq) {
        const size_t start = seq * chunk_size;
        const size_t len = std::min(chunk_size, payload.size() - start);

        std::vector<uint8_t> frag_payload =
            pack_frag_header(fragment_id, static_cast<uint16_t>(seq),
                             static_cast<uint16_t>(total), stream_id);
        frag_payload.insert(frag_payload.end(),
                            payload.begin() + start, payload.begin() + start + len);

        std::vector<uint8_t> frame = session_key_.has_value()
            ? pack_frame_mac(target, frag_payload, session_key_.value(), FLAG_FRAGMENTED)
            : pack_frame(target, frag_payload, FLAG_FRAGMENTED);
        write_all(frame);
    }
}

void VeyronClient::subscribe(const std::vector<std::string>& event_types) {
    Envelope env;
    auto* sub = env.mutable_subscribe();
    for (const auto& t : event_types)
        sub->add_event_types(t);
    send_envelope("kernel", env);
}

void VeyronClient::ack_event(const std::string& event_id) {
    Envelope env;
    env.mutable_event_ack()->set_event_id(event_id);
    send_envelope("kernel", env);
}

double VeyronClient::ping() {
    using clk = std::chrono::steady_clock;
    using sys = std::chrono::system_clock;

    Envelope env;
    auto* p = env.mutable_ping();
    p->set_timestamp(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            sys::now().time_since_epoch()).count()));

    auto t0 = clk::now();
    send_envelope("kernel", env);
    recv();
    return std::chrono::duration<double>(clk::now() - t0).count();
}

EventPublishAck VeyronClient::publish_event(const std::string& event_type,
                                            const std::vector<uint8_t>& payload_json,
                                            uint32_t timeout_ms) {
    Envelope env;
    auto* pub = env.mutable_event_publish();
    pub->set_event_type(event_type);
    pub->set_payload_json(payload_json.data(), payload_json.size());
    send_envelope("kernel", env);

    const auto timeout = std::chrono::milliseconds(timeout_ms == 0 ? 30000 : timeout_ms);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        auto frame = recv_frame_with_deadline(deadline);
        Envelope resp;
        if (!resp.ParseFromArray(frame.payload.data(), static_cast<int>(frame.payload.size())))
            throw std::runtime_error("veyron: protobuf parse failed");

        if (resp.has_event_publish_ack())
            return resp.event_publish_ack();
        if (resp.has_error())
            throw std::runtime_error("veyron: kernel error: " + resp.error().message() +
                                     " (" + resp.error().details() + ")");
        // unrelated traffic while waiting — discard, keep waiting
    }
}

void VeyronClient::write_all(const std::vector<uint8_t>& frame) {
    const uint8_t* ptr = frame.data();
    size_t remaining   = frame.size();
    while (remaining > 0) {
        ssize_t written = ::write(fd_, ptr, remaining);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            throw std::runtime_error("veyron: write() failed");
        ptr       += written;
        remaining -= static_cast<size_t>(written);
    }
}

void VeyronClient::send_envelope_no_mac(const std::string& target, const Envelope& env) {
    std::string bytes;
    env.SerializeToString(&bytes);
    write_all(pack_frame(target, bytes));
}

void VeyronClient::send_envelope(const std::string& target, const Envelope& env) {
    std::string bytes;
    env.SerializeToString(&bytes);

    std::vector<uint8_t> frame;
    if (session_key_.has_value()) {
        std::vector<uint8_t> payload(bytes.begin(), bytes.end());
        frame = pack_frame_mac(target, payload, session_key_.value());
    } else {
        frame = pack_frame(target, bytes);
    }
    write_all(frame);
}

} // namespace veyron
