#pragma once

#include <memory>

#include "contrib/http_wasm/filters/http/source/vm_runtime.h"
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace V8 {

std::unique_ptr<HttpWasm::Runtime> createV8Vm();

}
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
