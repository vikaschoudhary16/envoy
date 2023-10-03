#include "envoy/common/exception.h"

#include "source/extensions/common/http_wasm/guest.h"
#include "source/extensions/common/http_wasm/guest_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

// GuestConfig::GuestConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig&
// config)
//     : config_(config) {
//   if (config.has_environment_variables()) {
//     const auto& envs = config_.environment_variables();

//     // Check key duplication.
//     absl::flat_hash_set<std::string> keys;
//     for (const auto& env : envs.key_values()) {
//       keys.insert(env.first);
//     }
//     for (const auto& key : envs.host_env_keys()) {
//       if (!keys.insert(key).second) {
//         throw EnvoyException(
//             fmt::format("Key {} is duplicated in "
//                         "envoy.extensions.wasm.v3.VmConfig.environment_variables for {}. "
//                         "All the keys must be unique.",
//                         key, config_.name()));
//       }
//     }

//     // Construct merged key-value pairs.
//     for (const auto& env : envs.key_values()) {
//       envs_[env.first] = env.second;
//     }
//     for (const auto& key : envs.host_env_keys()) {
//       if (auto value = std::getenv(key.data())) {
//         envs_[key] = value;
//       }
//     }
//   }
// }

GuestConfig::GuestConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config)
    : name_(std::string(config.name())),
      configuration_(MessageUtil::anyToBytes(config.configuration())),
      fail_open_(config.fail_open()), config_(config), key_(name_ + "||" + configuration_),
      log_prefix_(makeLogPrefix()) {
  if (config.has_environment_variables()) {
    const auto& envs = config_.environment_variables();

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

std::string GuestConfig::makeLogPrefix() const {
  std::string prefix;
  if (!name_.empty()) {
    prefix = prefix + " " + name_;
  }
  return prefix;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
