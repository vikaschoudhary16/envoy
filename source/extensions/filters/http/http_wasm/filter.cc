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
  const auto initializedGuest = std::make_shared<InitializedGuest>(
      config, context.direction(), context.localInfo(), &context.listenerMetadata());

  auto callback = [initializedGuest, this](const GuestHandleSharedPtr& uninitialized_guest) {
    // NB: the Slot set() call doesn't complete inline, so all arguments must outlive this call.
    tls_slot_->set([uninitialized_guest, initializedGuest](Event::Dispatcher& dispatcher) {
      return std::make_shared<InitializedGuestHandleSharedPtrThreadLocal>(
          getOrCreateThreadLocalInitializedGuest(uninitialized_guest, initializedGuest,
                                                 dispatcher));
    });
  };

  if (!loadGuest(initializedGuest, context.scope().createScope(""), context.clusterManager(),
                 context.mainThreadDispatcher(), context.api(), context.lifecycleNotifier(),
                 std::move(callback))) {
    throw WasmException(
        fmt::format("http-wasm: Unable to load guest module {}", initializedGuest->name_));
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
