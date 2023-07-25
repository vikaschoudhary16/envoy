
#include <algorithm>
#include <memory>

#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/vm_runtime.h"
#include "contrib/http_wasm/filters/http/source/wasm_runtime_factory.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

using ContextBase = Host::ContextBase;
using Word = Host::Word;

Host::LogLevel EnvoyWasmVmIntegration::getLogLevel() {
  switch (ENVOY_LOGGER().level()) {
  case spdlog::level::trace:
    return Host::LogLevel::debug; // proxy_wasm spec defines debug as highest log level.
  case spdlog::level::debug:
    return Host::LogLevel::debug;
  case spdlog::level::info:
    return Host::LogLevel::info;
  case spdlog::level::warn:
    return Host::LogLevel::warn;
  case spdlog::level::err:
    return Host::LogLevel::error;
  default:
    return Host::LogLevel::none;
  }
}

void EnvoyWasmVmIntegration::error(std::string_view message) { ENVOY_LOG(error, message); }
void EnvoyWasmVmIntegration::debug(std::string_view message) { ENVOY_LOG(debug, message); }

bool isWasmEngineAvailable(absl::string_view runtime) {
  auto runtime_factory = Registry::FactoryRegistry<WasmRuntimeFactory>::getFactory(runtime);
  return runtime_factory != nullptr;
}

absl::string_view getFirstAvailableWasmEngineName() {
  constexpr absl::string_view wasm_engines[] = {
      "envoy.wasm.runtime.v8", "envoy.wasm.runtime.wasmtime", "envoy.wasm.runtime.wamr",
      "envoy.wasm.runtime.wavm"};
  for (const auto wasm_engine : wasm_engines) {
    if (isWasmEngineAvailable(wasm_engine)) {
      return wasm_engine;
    }
  }
  return "";
}

WasmVmPtr createWasmVm(absl::string_view runtime) {
  // Set wasm runtime to built-in Wasm engine if it is not specified
  if (runtime.empty()) {
    runtime = getFirstAvailableWasmEngineName();
  }

  auto runtime_factory = Registry::FactoryRegistry<WasmRuntimeFactory>::getFactory(runtime);
  if (runtime_factory == nullptr) {
    ENVOY_LOG_TO_LOGGER(
        Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), warn,
        "Failed to create Wasm VM using {} runtime. Envoy was compiled without support for it",
        runtime);
    return nullptr;
  }

  auto wasm = runtime_factory->createWasmVm();
  wasm->integration() = std::make_unique<EnvoyWasmVmIntegration>();
  return wasm;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
