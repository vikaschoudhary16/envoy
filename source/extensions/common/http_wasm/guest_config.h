#pragma once

#include <memory>

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"
#include "envoy/local_info/local_info.h"

#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

//clang-format off
using EnvironmentVariableMap = std::unordered_map<std::string, std::string>;
struct SanitizationConfig {
  std::vector<std::string> argument_list;
  bool is_allowlist;
};
using AllowedCapabilitiesMap = std::unordered_map<std::string, SanitizationConfig>;
// clang-format on

class Context;
class GuestConfig {
public:
  GuestConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config);
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config() { return config_; }
  AllowedCapabilitiesMap& allowedCapabilities() { return allowed_capabilities_; }
  EnvironmentVariableMap& environmentVariables() { return envs_; }

private:
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig config_;
  AllowedCapabilitiesMap allowed_capabilities_{};
  EnvironmentVariableMap envs_;
};

using GuestConfigPtr = std::unique_ptr<GuestConfig>;

// InitializedGuest contains the information for a filter/service.
class InitializedGuest {
public:
  InitializedGuest(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config,
                   envoy::config::core::v3::TrafficDirection direction,
                   const LocalInfo::LocalInfo& local_info,
                   const envoy::config::core::v3::Metadata* listener_metadata)
      : name_(std::string(config.name())),
        configuration_(MessageUtil::anyToBytes(config.configuration())),
        fail_open_(config.fail_open()), direction_(direction), local_info_(local_info),
        listener_metadata_(listener_metadata), wasm_config_(std::make_unique<GuestConfig>(config)),
        key_(name_ + "||" + configuration_ + "||" +
             std::string(createInitializedGuestKey(config, direction, listener_metadata))),
        log_prefix_(makeLogPrefix()) {}

  envoy::config::core::v3::TrafficDirection& direction() { return direction_; }
  const LocalInfo::LocalInfo& localInfo() { return local_info_; }
  const envoy::config::core::v3::Metadata* listenerMetadata() { return listener_metadata_; }
  GuestConfig& wasmConfig() { return *wasm_config_; }
  const std::string name_;
  const std::string configuration_;
  const bool fail_open_;

  const std::string& key() const { return key_; }
  const std::string& log_prefix() const { return log_prefix_; }

private:
  static std::string createInitializedGuestKey(
      const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config,
      envoy::config::core::v3::TrafficDirection direction,
      const envoy::config::core::v3::Metadata* listener_metadata) {
    return config.name() + "||" + envoy::config::core::v3::TrafficDirection_Name(direction) +
           (listener_metadata ? "||" + std::to_string(MessageUtil::hash(*listener_metadata)) : "");
  }

private:
  envoy::config::core::v3::TrafficDirection direction_;
  const LocalInfo::LocalInfo& local_info_;
  const envoy::config::core::v3::Metadata* listener_metadata_;
  GuestConfigPtr wasm_config_;

private:
  std::string makeLogPrefix() const;

  const std::string key_;
  const std::string log_prefix_;
};

using InitializedGuestSharedPtr = std::shared_ptr<InitializedGuest>;
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
