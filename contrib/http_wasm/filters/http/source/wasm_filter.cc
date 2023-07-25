#include "contrib/http_wasm/filters/http/source/wasm_filter.h"
#include "contrib/http_wasm/filters/http/source/plugin.h"
#include "contrib/http_wasm/filters/http/source/vm.h"
#include "contrib/http_wasm/filters/http/source/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

FilterConfig::FilterConfig(const envoy::extensions::filters::http::http_wasm::v3alpha::Wasm& config,
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

  if (!createWasm(plugin, context.scope().createScope(""), context.clusterManager(),
                  context.initManager(), context.mainThreadDispatcher(), context.api(),
                  context.lifecycleNotifier(), remote_data_provider_, std::move(callback))) {
    throw WasmException(
        fmt::format("Unable to create Wasm(http-wasm) HTTP filter {}", plugin->name_));
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
