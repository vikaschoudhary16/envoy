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
    Guest* guest = nullptr;
    if (!tls_slot_->currentThreadRegistered()) {
      return nullptr;
    }
    GuestAndGuestConfigSharedPtr mapping = tls_slot_->get()->mapping();
    if (!mapping) {
      return nullptr;
    }
    if (mapping->guest()) {
      guest = mapping->guest().get();
    }
    if (!guest || guest->isFailed()) {
      if (mapping->guestConfig()->fail_open_) {
        return nullptr; // Fail open skips adding this filter to callbacks.
      } else {
        return std::make_shared<Context>(
            nullptr,
            mapping->guestConfig()); // Fail closed is handled by an empty Context.
      }
    }
    return std::make_shared<Context>(guest, mapping->guestConfig());
  }

private:
  ThreadLocal::TypedSlotPtr<GuestAndGuestConfigSharedPtrThreadLocal> tls_slot_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
