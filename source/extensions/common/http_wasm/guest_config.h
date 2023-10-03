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
// clang-format on

class GuestConfig {
public:
  GuestConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config);
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config() { return config_; }
  EnvironmentVariableMap& environmentVariables() { return envs_; }
  std::string name_;
  bool fail_open_;
  std::string configuration_;
  std::string& log_prefix() { return log_prefix_; }
  const std::string& key() const { return key_; }

private:
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig config_;
  EnvironmentVariableMap envs_;
  const std::string key_;
  std::string log_prefix_;
  std::string makeLogPrefix() const;
};

using GuestConfigPtr = std::unique_ptr<GuestConfig>;

// InitializedGuest contains the information for a filter/service.
// class InitializedGuest {
// public:
//   InitializedGuest(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config)
//       : name_(std::string(config.name())),
//         configuration_(MessageUtil::anyToBytes(config.configuration())),
//         fail_open_(config.fail_open()), wasm_config_(std::make_unique<GuestConfig>(config)),
//         key_(name_ + "||" + configuration_ + "||" +
//         std::string(createInitializedGuestKey(config))), log_prefix_(makeLogPrefix()) {}

//   GuestConfig& wasmConfig() { return *wasm_config_; }
//   std::string name_;
//   std::string configuration_;
//   bool fail_open_;

//   const std::string& key() const { return key_; }
//   std::string& log_prefix() { return log_prefix_; }

// private:
//   static std::string createInitializedGuestKey(
//       const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config) {
//     return config.name();
//   }

// private:
//   GuestConfigPtr wasm_config_;

// private:
//   std::string makeLogPrefix() const;

//   const std::string key_;
//   std::string log_prefix_;
// };

using GuestConfigSharedPtr = std::shared_ptr<GuestConfig>;
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
