#include "source/extensions/filters/http/http_wasm/filter.h"
#include "source/extensions/common/http_wasm/plugin.h"
#include "source/extensions/common/http_wasm/vm.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

FilterConfig::FilterConfig(const envoy::extensions::filters::http::http_wasm::v3::Wasm& config,
                           Server::Configuration::FactoryContext& context)
    : tls_slot_(ThreadLocal::TypedSlot<PluginHandleSharedPtrThreadLocal>::makeUnique(
          context.threadLocal())) {
  const auto plugin = std::make_shared<Plugin>(config.config(), context.direction(),
                                               context.localInfo(), &context.listenerMetadata());

  auto callback = [plugin, this](const WasmHandleSharedPtr& base_wasm) {
    // NB: the Slot set() call doesn't complete inline, so all arguments must outlive this call.
    tls_slot_->set([base_wasm, plugin](Event::Dispatcher& dispatcher) {
      return std::make_shared<PluginHandleSharedPtrThreadLocal>(
          getOrCreateThreadLocalPlugin(base_wasm, plugin, dispatcher));
    });
  };

  if (!createVm(plugin, context.scope().createScope(""), context.clusterManager(),
                context.mainThreadDispatcher(), context.api(), context.lifecycleNotifier(),
                std::move(callback))) {
    throw WasmException(
        fmt::format("Unable to create Wasm(http-wasm) HTTP filter {}", plugin->name_));
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
