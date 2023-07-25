#pragma once

#include "envoy/common/pure.h"
#include "envoy/config/typed_config.h"

#include "absl/strings/string_view.h"
#include "contrib/http_wasm/filters/http/source/host/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

using WasmVmPtr = std::unique_ptr<Host::WasmVm>;

class WasmRuntimeFactory : public Config::UntypedFactory {
public:
  ~WasmRuntimeFactory() override = default;
  virtual WasmVmPtr createWasmVm() PURE;

  std::string category() const override { return "envoy.http_wasm.runtime"; }
};

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
