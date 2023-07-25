#include "envoy/registry/registry.h"

#include "contrib/http_wasm/filters/http/source/wasm_runtime_factory.h"
#include "contrib/http_wasm/filters/http/source/host/v8.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class V8RuntimeFactory : public WasmRuntimeFactory {
public:
  WasmVmPtr createWasmVm() override { return createV8Vm(); }

  std::string name() const override { return "envoy.http_wasm.runtime.v8"; }
};
REGISTER_FACTORY(V8RuntimeFactory, WasmRuntimeFactory);

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
