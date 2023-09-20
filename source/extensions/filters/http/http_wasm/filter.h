#pragma once

#include <memory>

#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/upstream/cluster_manager.h"

#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"
#include "source/extensions/common/http_wasm/guest_config.h"
#include "source/extensions/common/http_wasm/context.h"
#include "source/extensions/common/http_wasm/guest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class FilterConfig : Logger::Loggable<Logger::Id::wasm> {
public:
  FilterConfig(const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config,
               Server::Configuration::FactoryContext& context);

  std::shared_ptr<Context> createFilter() {
    Guest* wasm = nullptr;
    if (!tls_slot_->currentThreadRegistered()) {
      return nullptr;
    }
    InitializedGuestHandleSharedPtr handle = tls_slot_->get()->handle();
    if (!handle) {
      return nullptr;
    }
    if (handle->wasmHandle()) {
      wasm = handle->wasmHandle()->guest().get();
    }
    if (!wasm || wasm->isFailed()) {
      if (handle->initializedGuest()->fail_open_) {
        return nullptr; // Fail open skips adding this filter to callbacks.
      } else {
        return std::make_shared<Context>(nullptr, 0,
                                         handle); // Fail closed is handled by an empty Context.
      }
    }
    return std::make_shared<Context>(wasm, handle->rootContextId(), handle);
  }

private:
  ThreadLocal::TypedSlotPtr<InitializedGuestHandleSharedPtrThreadLocal> tls_slot_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
