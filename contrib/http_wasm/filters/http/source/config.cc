#include "envoy/registry/registry.h"

#include "source/common/common/empty_string.h"
#include "source/common/config/datasource.h"

#include "contrib/envoy/extensions/filters/http/http_wasm/v3alpha/wasm.pb.validate.h"
#include "contrib/http_wasm/filters/http/source/wasm_filter.h"
#include "contrib/http_wasm/filters/http/source/config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

Http::FilterFactoryCb HttpWasmFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::http_wasm::v3alpha::Wasm& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  // context.api().customStatNamespaces().registerStatNamespace(
  //     Extensions::Common::Wasm::CustomStatNamespace);
  auto filter_config = std::make_shared<FilterConfig>(proto_config, context);
  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    auto filter = filter_config->createFilter();
    if (!filter) { // Fail open
      return;
    }
    callbacks.addStreamFilter(filter);
    // callbacks.addAccessLogHandler(filter);
  };
}

/**
 * Static registration for the Wasm filter. @see RegisterFactory.
 */
REGISTER_FACTORY(HttpWasmFilterConfig, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
