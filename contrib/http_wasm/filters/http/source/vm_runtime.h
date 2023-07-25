#pragma once

#include <memory>

#include "envoy/common/exception.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats.h"

#include "source/common/common/logger.h"

#include "absl/strings/str_cat.h"
#include "contrib/http_wasm/filters/http/source/host/vm_runtime.h"
#include "contrib/http_wasm/filters/http/source/host/word.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

// providing logger to Wasm VM.
class EnvoyWasmVmIntegration : public Host::WasmVmIntegration, Logger::Loggable<Logger::Id::wasm> {
public:
  // Host::WasmVmIntegration
  Host::WasmVmIntegration* clone() override { return new EnvoyWasmVmIntegration(); }
  Host::LogLevel getLogLevel() override;
  void error(std::string_view message) override;
  void debug(std::string_view message) override;
};

// Exceptions for issues with the WebAssembly code.
class WasmException : public EnvoyException {
public:
  using EnvoyException::EnvoyException;
};

using WasmVmPtr = std::unique_ptr<Host::WasmVm>;

// Create a new low-level Wasm VM using runtime of the given type (e.g. "envoy.wasm.runtime.wavm").
WasmVmPtr createWasmVm(absl::string_view runtime);

/**
 * @return true if the provided Wasm Engine is compiled with Envoy
 */
bool isWasmEngineAvailable(absl::string_view runtime);

/**
 * @return the name of the first available Wasm Engine compiled with Envoy
 */
absl::string_view getFirstAvailableWasmEngineName();

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
