#include <gtest/gtest.h>
#include <cstdlib>
#include "veyron/plugin.hpp"

using namespace veyron;

namespace {
class NoopPlugin : public Plugin {
public:
    using Plugin::Plugin;
    void on_message(const Envelope&) override {}
};
} // namespace

TEST(PluginConstruction, PicksUpJwtTokenFromEnv) {
    setenv("VEYRON_JWT_TOKEN", "tok-from-env", 1);
    NoopPlugin plugin("test-plugin");
    EXPECT_EQ(plugin.jwt_token(), "tok-from-env");
    unsetenv("VEYRON_JWT_TOKEN");
}

TEST(PluginConstruction, NeverDefaultsSocketToSharedTmp) {
    unsetenv("XDG_RUNTIME_DIR");
    NoopPlugin plugin("test-plugin");
    EXPECT_NE(plugin.socket_path(), "/tmp/veyron.sock");
}
