#include "envoy/registry/registry.h"

#include "source/common/common/empty_string.h"
#include "source/common/config/datasource.h"

#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"
#include "source/extensions/filters/http/http_wasm/filter.h"
#include "source/extensions/filters/http/http_wasm/config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

Http::FilterFactoryCb HttpWasmFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  auto filter_config = std::make_shared<FilterConfig>(proto_config, context);
  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    auto filter = filter_config->createFilter();
    if (!filter) { // Fail open
      return;
    }
    callbacks.addStreamFilter(filter);
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
