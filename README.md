# veyron-sdk (C++)

C++ SDK for writing [Veyron](https://github.com/veyron-core/veyron) plugins.

A Veyron plugin is a separate OS process supervised by the Veyron kernel. It
talks to the kernel over a Unix domain socket using the Veyron wire protocol:
framed messages carrying Protobuf envelopes, with optional zstd compression,
HMAC-SHA256 frame authentication, and fragmentation.

## Requirements

- CMake ≥ 3.20, C++17
- Protobuf, OpenSSL, Abseil, libzstd (pkg-config), GTest (for tests)

## Build

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build
```

## Quick start

```cpp
#include "veyron/plugin.hpp"

class EchoPlugin : public veyron::Plugin {
public:
    EchoPlugin() : veyron::Plugin("echo-plugin") {}

    void on_message(const veyron::Envelope& env) override {
        if (!env.has_action_request()) return;
        // handle env.action_request(), reply via client()
    }
};

int main() {
    EchoPlugin plugin;
    plugin.run();
}
```

`Plugin::run` connects, registers, and serves until the kernel asks the
plugin to shut down. The SDK answers `Ping` automatically and exits the loop
on `PluginShutdown`. See `examples/echo_plugin.cpp` for a fuller example.

## Environment

| Variable             | Meaning                                                        |
|----------------------|-----------------------------------------------------------------|
| `VEYRON_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.veyron/run` (never shared `/tmp`). |
| `VEYRON_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VEYRON_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Consuming via CMake

```cmake
find_package(veyron-sdk REQUIRED)
target_link_libraries(my_plugin PRIVATE veyron::sdk)
```

## License

MIT
