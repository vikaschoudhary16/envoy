
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

RuntimePtr createV8Runtime() {
  auto runtime = V8::createV8();
  runtime->logger() = std::make_unique<WasmScopeLogger>();
  return runtime;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
