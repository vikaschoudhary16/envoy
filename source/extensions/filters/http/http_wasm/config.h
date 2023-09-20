#pragma once

#include "source/extensions/filters/http/common/factory_base.h"

//#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.h"
#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

/**
 * Config registration for the HttpWasm filter. @see NamedHttpFilterConfigFactory.
 */
class HttpWasmFilterConfig
    : public Common::FactoryBase<envoy::extensions::filters::http::http_wasm::v3::GuestConfig> {
public:
  HttpWasmFilterConfig() : FactoryBase("envoy.filters.http.http_wasm") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::http_wasm::v3::GuestConfig& proto_config,
      const std::string&, Server::Configuration::FactoryContext& context) override;
};

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
