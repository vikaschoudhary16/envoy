#pragma once

#include <memory>

#include "contrib/http_wasm/filters/http/source/host/vm_runtime.h"
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

std::unique_ptr<Host::WasmVm> createV8Vm();

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
