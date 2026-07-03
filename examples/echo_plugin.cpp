// Lightweight demo plugin for the Veyron C++ SDK.
//
// Shows: lifecycle hooks, event subscription, action handling, and
// emitting a response back to the kernel.
//
// Run (with a kernel listening on the default socket):
//     VEYRON_JWT_TOKEN=<token> ./echo_plugin

#include <iostream>

#include "veyron/plugin.hpp"

using namespace veyron;

namespace {

class EchoPlugin : public Plugin {
public:
    using Plugin::Plugin;

    void on_init() override {
        std::cout << "[" << plugin_id_ << "] registered, subscribing to events\n";
        client_.subscribe({"system.low_memory"});
    }

    void on_message(const Envelope& env) override {
        if (env.has_action_request()) {
            handle_action(env.action_request());
        } else if (env.has_event()) {
            handle_event(env.event());
        } else {
            std::cout << "[" << plugin_id_ << "] unhandled message (case "
                      << env.payload_case() << ")\n";
        }
    }

    void on_shutdown() override {
        std::cout << "[" << plugin_id_ << "] shutting down\n";
    }

private:
    void handle_action(const ActionRequest& req) {
        Envelope out;
        auto* resp = out.mutable_action_response();
        resp->set_action_id(req.action_id());
        if (req.action() == "echo") {
            resp->set_status(ActionStatus::ACTION_OK);
            resp->set_data_json(req.params_json());
        } else {
            resp->set_status(ActionStatus::ACTION_NOT_FOUND);
            resp->set_error("unknown action: " + req.action());
        }
        client_.send("kernel", out);
    }

    void handle_event(const Event& evt) {
        std::cout << "[" << plugin_id_ << "] event " << evt.event_type()
                  << ": " << evt.payload_json() << "\n";
    }
};

} // namespace

int main() {
    EchoPlugin plugin("echo-plugin");
    plugin.run();
    return 0;
}
