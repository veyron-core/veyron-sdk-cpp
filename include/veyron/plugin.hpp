#pragma once

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

#include "veyron/client.hpp"
#include "veyron/env.hpp"

namespace veyron {

class Plugin {
public:
    // socket_path: explicit override, else VEYRON_SOCKET_PATH resolution
    // mirroring the kernel (XDG_RUNTIME_DIR -> /run/user/<uid> -> ~/.veyron/run).
    // Never the world-writable shared /tmp (BUG-006).
    // jwt_token/secret: explicit override, else VEYRON_JWT_TOKEN/VEYRON_JWT_SECRET
    // (secured-kernel support, R5-05).
    explicit Plugin(std::string plugin_id,
                    std::string socket_path = "",
                    std::vector<uint8_t> secret = {},
                    std::string jwt_token = "")
        : plugin_id_(std::move(plugin_id))
        , jwt_token_(resolve_jwt_token(jwt_token))
        , socket_path_(socket_path.empty() ? default_socket_path() : std::move(socket_path))
        , client_(socket_path_, resolve_jwt_secret(secret)) {}

    virtual ~Plugin() = default;

    virtual void on_init() {}
    virtual void on_message(const Envelope& env) = 0;
    virtual void on_shutdown() {}

    // Declared capabilities: permissions, provided actions, event
    // subscriptions, IPC targets. Default is empty (mirrors the Rust SDK's
    // Plugin::manifest) — override to unlock IPC send / action-provider
    // routing, both of which the kernel default-denies on an empty manifest.
    virtual PluginManifest manifest() const { return PluginManifest{}; }

    const std::string& jwt_token() const { return jwt_token_; }
    const std::string& socket_path() const { return socket_path_; }

    void run() {
        client_.connect();

        Envelope ack = client_.register_plugin(plugin_id_, manifest(), jwt_token_);
        if (!ack.plugin_register_ack().accepted()) {
            throw std::runtime_error(
                "veyron: registration rejected: " +
                ack.plugin_register_ack().reject_reason());
        }

        on_init();
        try {
            while (true) {
                Envelope env = client_.recv();
                if (env.has_plugin_shutdown()) break;
                if (env.has_ping()) {
                    // Answer the kernel watchdog directly — a supervised plugin
                    // whose last Pong goes stale is SIGKILLed (AUDIT H-02).
                    Envelope pong;
                    pong.mutable_pong()->set_original_timestamp(env.ping().timestamp());
                    pong.mutable_pong()->set_server_timestamp(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                    client_.send("kernel", pong);
                    continue;
                }
                on_message(env);
            }
        } catch (...) {
            on_shutdown();
            client_.close();
            throw;
        }
        on_shutdown();
        client_.close();
    }

protected:
    std::string  plugin_id_;
    std::string  jwt_token_;
    std::string  socket_path_;
    VeyronClient client_;
};

} // namespace veyron
