#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "veyron/framing.hpp"
#include "veyron/mac.hpp"
#include "veyron_protocol.pb.h"

namespace veyron {

class VeyronClient {
public:
    // secret: shared JWT secret for MAC key derivation.
    // Pass empty vector (default) to skip MAC — only valid with allow_no_auth:true kernels.
    explicit VeyronClient(std::string socket_path,
                          std::vector<uint8_t> secret = {});
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

    void   subscribe(const std::vector<std::string>& event_types);
    double ping();

private:
    std::string                            socket_path_;
    int                                    fd_ = -1;
    std::string                            plugin_id_;
    std::vector<uint8_t>                   secret_;
    std::optional<std::array<uint8_t,32>>  session_key_;

    // Send without MAC regardless of session_key_ (used for registration handshake).
    void send_envelope_no_mac(const std::string& target, const Envelope& env);
    // Send with MAC when session_key_ is set, else CRC-only.
    void send_envelope(const std::string& target, const Envelope& env);
};

} // namespace veyron
