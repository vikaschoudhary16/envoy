
#include <algorithm>
#include <memory>

#include "source/extensions/common/http_wasm/context.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"
#include "source/extensions/common/http_wasm/http_wasm_enums.h"
#include "source/extensions/common/http_wasm/v8/v8.h"
#include "vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

LogLevel WasmScopeLogger::getLogLevel() {
  switch (ENVOY_LOGGER().level()) {
  case spdlog::level::trace:
    return LogLevel::debug;
  case spdlog::level::debug:
    return LogLevel::debug;
  case spdlog::level::info:
    return LogLevel::info;
  case spdlog::level::warn:
    return LogLevel::warn;
  case spdlog::level::err:
    return LogLevel::error;
  default:
    return LogLevel::none;
  }
}

void WasmScopeLogger::error(std::string_view message) { ENVOY_LOG(error, message); }
void WasmScopeLogger::debug(std::string_view message) { ENVOY_LOG(debug, message); }

RuntimePtr createV8Runtime() {
  auto runtime_client = V8::createV8Vm();
  runtime_client->logger() = std::make_unique<WasmScopeLogger>();
  return runtime_client;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
