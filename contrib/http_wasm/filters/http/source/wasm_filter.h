#pragma once

#include <memory>

#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/upstream/cluster_manager.h"

#include "contrib/envoy/extensions/filters/http/http_wasm/v3alpha/wasm.pb.validate.h"
#include "contrib/http_wasm/filters/http/source/plugin.h"
#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/vm.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class FilterConfig : Logger::Loggable<Logger::Id::wasm> {
public:
  FilterConfig(const envoy::extensions::filters::http::http_wasm::v3alpha::Wasm& config,
               Server::Configuration::FactoryContext& context);

  std::shared_ptr<Context> createFilter() {
    Wasm* wasm = nullptr;
    if (!tls_slot_->currentThreadRegistered()) {
      return nullptr;
    }
    PluginHandleSharedPtr handle = tls_slot_->get()->handle();
    if (!handle) {
      return nullptr;
    }
    if (handle->wasmHandle()) {
      wasm = handle->wasmHandle()->wasm().get();
    }
    if (!wasm || wasm->isFailed()) {
      if (handle->plugin()->fail_open_) {
        return nullptr; // Fail open skips adding this filter to callbacks.
      } else {
        return std::make_shared<Context>(nullptr, 0,
                                         handle); // Fail closed is handled by an empty Context.
      }
    }
    return std::make_shared<Context>(wasm, handle->rootContextId(), handle);
  }

private:
  ThreadLocal::TypedSlotPtr<PluginHandleSharedPtrThreadLocal> tls_slot_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
