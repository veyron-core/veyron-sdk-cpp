#include "veyron/env.hpp"

#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace veyron {

namespace {
bool is_directory(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}
} // namespace

std::string default_socket_path() {
    if (const char* explicit_path = std::getenv("VEYRON_SOCKET_PATH"); explicit_path && *explicit_path) {
        return std::string(explicit_path);
    }
    if (const char* xdg = std::getenv("XDG_RUNTIME_DIR"); xdg && *xdg) {
        return std::string(xdg) + "/veyron.sock";
    }
    std::string run_user = "/run/user/" + std::to_string(getuid());
    if (is_directory(run_user)) {
        return run_user + "/veyron.sock";
    }
    const char* home = std::getenv("HOME");
    return std::string(home ? home : "") + "/.veyron/run/veyron.sock";
}

std::string resolve_jwt_token(const std::string& explicit_token) {
    if (!explicit_token.empty()) {
        return explicit_token;
    }
    if (const char* tok = std::getenv("VEYRON_JWT_TOKEN"); tok && *tok) {
        return std::string(tok);
    }
    return "";
}

std::vector<uint8_t> resolve_jwt_secret(const std::vector<uint8_t>& explicit_secret) {
    if (!explicit_secret.empty()) {
        return explicit_secret;
    }
    if (const char* secret = std::getenv("VEYRON_JWT_SECRET"); secret && *secret) {
        return std::vector<uint8_t>(secret, secret + std::string(secret).size());
    }
    return {};
}

} // namespace veyron
