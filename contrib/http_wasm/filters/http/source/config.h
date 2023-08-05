#pragma once

#include "source/extensions/filters/http/common/factory_base.h"

#include "contrib/envoy/extensions/filters/http/http_wasm/v3alpha/wasm.pb.h"
#include "contrib/envoy/extensions/filters/http/http_wasm/v3alpha/wasm.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

/**
 * Config registration for the HttpWasm filter. @see NamedHttpFilterConfigFactory.
 */
class HttpWasmFilterConfig
    : public Common::FactoryBase<envoy::extensions::filters::http::http_wasm::v3alpha::Wasm> {
public:
  HttpWasmFilterConfig() : FactoryBase("envoy.filters.http.http_wasm") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::http_wasm::v3alpha::Wasm& proto_config,
      const std::string&, Server::Configuration::FactoryContext& context) override;
};

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
