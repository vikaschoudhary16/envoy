#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"
#include "source/extensions/common/http_wasm/context.h"
#include "source/extensions/filters/http/http_wasm/config.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class WasmFilterConfigTest : public testing::Test {
protected:
  WasmFilterConfigTest() : api_(Api::createApiForTest(stats_store_)) {
    ON_CALL(context_, api()).WillByDefault(ReturnRef(*api_));
    ON_CALL(context_, scope()).WillByDefault(ReturnRef(stats_scope_));
    ON_CALL(context_, listenerMetadata()).WillByDefault(ReturnRef(listener_metadata_));
    EXPECT_CALL(context_, initManager()).WillRepeatedly(ReturnRef(init_manager_));
    ON_CALL(context_, clusterManager()).WillByDefault(ReturnRef(cluster_manager_));
    ON_CALL(context_, mainThreadDispatcher()).WillByDefault(ReturnRef(dispatcher_));
  }

  NiceMock<Server::Configuration::MockFactoryContext> context_;
  Stats::IsolatedStoreImpl stats_store_;
  Stats::Scope& stats_scope_{*stats_store_.rootScope()};
  Api::ApiPtr api_;
  envoy::config::core::v3::Metadata listener_metadata_;
  Init::ManagerImpl init_manager_{"init_manager"};
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  Init::ExpectableWatcherImpl init_watcher_;
  NiceMock<Event::MockDispatcher> dispatcher_;
};

TEST_F(WasmFilterConfigTest, YamlLoadFromFileWasm) {
  const std::string yaml = TestEnvironment::substitute(absl::StrCat(R"EOF(
  max_request_bytes: 5242880
  configuration:
     "@type": "type.googleapis.com/google.protobuf.StringValue"
     value: "some configuration"
  code:
    local:
      filename: "{{ test_rundir }}/test/extensions/filters/http/http_wasm/test_data/req-header/envoy-tests.wasm"
  )EOF"));

  envoy::extensions::filters::http::http_wasm::v3::GuestConfig proto_config;
  TestUtility::loadFromYaml(yaml, proto_config);

  // Intentionally we scope the factory here, and make the context outlive it.
  // This case happens when the config is updated by ECDS, and
  // we have to make sure that contexts still hold valid WasmVMs in these cases.
  std::shared_ptr<Envoy::Extensions::HttpFilters::HttpWasm::Context> context = nullptr;
  {
    HttpWasmFilterConfig factory;
    Http::FilterFactoryCb cb =
        factory.createFilterFactoryFromProto(proto_config, "stats", context_);
    EXPECT_CALL(init_watcher_, ready());
    context_.initManager().initialize(init_watcher_);
    EXPECT_EQ(context_.initManager().state(), Init::Manager::State::Initialized);
    Http::MockFilterChainFactoryCallbacks filter_callback;
    EXPECT_CALL(filter_callback, addStreamFilter(_))
        .WillOnce([&context](Http::StreamFilterSharedPtr filter) {
          context =
              std::static_pointer_cast<Envoy::Extensions::HttpFilters::HttpWasm::Context>(filter);
        });
    cb(filter_callback);
  }
  // Check if the context still holds a valid Wasm even after the factory is destroyed.
  EXPECT_TRUE(context);
  EXPECT_TRUE(context->guest());
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
