#include "envoy/common/exception.h"

#include "contrib/http_wasm/filters/http/source/host/vm.h"
#include "contrib/http_wasm/filters/http/source/plugin.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

WasmConfig::WasmConfig(const envoy::extensions::wasm::v3::PluginConfig& config) : config_(config) {
  for (auto& capability : config_.capability_restriction_config().allowed_capabilities()) {
    // TODO(vikas): Set the SanitizationConfig fields once sanitization is implemented.
    allowed_capabilities_[capability.first] = Host::SanitizationConfig();
  }

  if (config_.vm_config().has_environment_variables()) {
    const auto& envs = config_.vm_config().environment_variables();

    // Check key duplication.
    absl::flat_hash_set<std::string> keys;
    for (const auto& env : envs.key_values()) {
      keys.insert(env.first);
    }
    for (const auto& key : envs.host_env_keys()) {
      if (!keys.insert(key).second) {
        throw EnvoyException(
            fmt::format("Key {} is duplicated in "
                        "envoy.extensions.wasm.v3.VmConfig.environment_variables for {}. "
                        "All the keys must be unique.",
                        key, config_.name()));
      }
    }

    // Construct merged key-value pairs.
    for (const auto& env : envs.key_values()) {
      envs_[env.first] = env.second;
    }
    for (const auto& key : envs.host_env_keys()) {
      if (auto value = std::getenv(key.data())) {
        envs_[key] = value;
      }
    }
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
