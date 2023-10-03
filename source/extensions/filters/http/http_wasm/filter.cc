#include "source/extensions/filters/http/http_wasm/filter.h"
#include "source/extensions/common/http_wasm/guest_config.h"
#include "source/extensions/common/http_wasm/guest.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

FilterConfig::FilterConfig(
    const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& config,
    Server::Configuration::FactoryContext& context)
    : tls_slot_(ThreadLocal::TypedSlot<InitializedGuestHandleSharedPtrThreadLocal>::makeUnique(
          context.threadLocal())) {
  auto guestConfig = std::make_shared<GuestConfig>(config);

  auto callback = [guestConfig, this](const GuestHandleSharedPtr& loaded_guest_code) {
    // NB: the Slot set() call doesn't complete inline, so all arguments must outlive this call.
    tls_slot_->set([loaded_guest_code, guestConfig](Event::Dispatcher& dispatcher) {
      return std::make_shared<InitializedGuestHandleSharedPtrThreadLocal>(
          getOrCreateThreadLocalInitializedGuest(loaded_guest_code, guestConfig, dispatcher));
    });
  };

  if (!loadGuest(guestConfig, context.scope().createScope(""), context.clusterManager(),
                 context.mainThreadDispatcher(), context.api(), context.lifecycleNotifier(),
                 std::move(callback))) {
    throw WasmException(
        fmt::format("http-wasm: Unable to load guest module {}", guestConfig->name_));
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
