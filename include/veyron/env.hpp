#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace veyron {

// Per-user socket location, mirroring the kernel's default_socket_path()
// (src/utils/config.rs) and the Python SDK's _default_socket_path():
// XDG_RUNTIME_DIR -> /run/user/<uid> -> ~/.veyron/run. Never the
// world-writable shared /tmp (BUG-006).
std::string default_socket_path();

// Resolves the JWT token to present at registration: explicit_token if
// non-empty, else VEYRON_JWT_TOKEN, else "".
std::string resolve_jwt_token(const std::string& explicit_token);

// Resolves the shared secret for frame MACs: explicit_secret if non-empty,
// else the bytes of VEYRON_JWT_SECRET, else empty (no MAC).
std::vector<uint8_t> resolve_jwt_secret(const std::vector<uint8_t>& explicit_secret);

} // namespace veyron
