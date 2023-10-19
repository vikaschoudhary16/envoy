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
// clang-format on

class GuestConfig {
public:
  GuestConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config);
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config() { return config_; }
  EnvironmentVariableMap& environmentVariables() { return envs_; }
  std::string name_;
  bool fail_open_;
  std::string configuration_;
  const std::string& key() const { return key_; }

private:
  envoy::extensions::filters::http::http_wasm::v3::GuestConfig config_;
  EnvironmentVariableMap envs_;
  const std::string key_;
};

using GuestConfigPtr = std::unique_ptr<GuestConfig>;
using GuestConfigSharedPtr = std::shared_ptr<GuestConfig>;
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
