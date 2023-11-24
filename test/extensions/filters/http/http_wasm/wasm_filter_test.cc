#include "envoy/grpc/async_client.h"

#include "source/common/http/message_impl.h"
#include "source/extensions/filters/http/http_wasm/filter.h"

#include "source/extensions/common/http_wasm/vm_runtime.h"
#include "test/mocks/network/connection.h"
#include "test/mocks/router/mocks.h"
#include "test/test_common/wasm_base.h"

using testing::_;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

#define MOCK_CONTEXT_LOG_                                                                          \
  using Context::log;                                                                              \
  WasmResult log(int32_t level, std::string_view message) override {                               \
    log_(static_cast<LogLevel>(level), toAbslStringView(message));                                 \
    return WasmResult::Ok;                                                                         \
  }                                                                                                \
  MOCK_METHOD(void, log_, (LogLevel level, absl::string_view message))

class TestFilter : public Envoy::Extensions::HttpFilters::HttpWasm::Context {
public:
  TestFilter(std::shared_ptr<Guest> guest, GuestConfigSharedPtr& guest_config)
      : Context(guest, guest_config) {}
  MOCK_CONTEXT_LOG_;
};

class WasmHttpFilterTest : public testing::Test {
public:
  WasmHttpFilterTest()
      : symbol_table_(std::make_unique<Stats::SymbolTableImpl>()),
        store_(std::make_unique<Stats::IsolatedStoreImpl>(*symbol_table_)), pool_(*symbol_table_) {}
  ~WasmHttpFilterTest() override { pool_.clear(); };

  void setupFilter() {
    context_ = std::make_unique<TestFilter>(guest_, guest_config_);
    context_->setDecoderFilterCallbacks(decoder_callbacks_);
    context_->setEncoderFilterCallbacks(encoder_callbacks_);
  }

  TestFilter& filter() { return *static_cast<TestFilter*>(context_.get()); }

  void setup() {
    Api::ApiPtr api = Api::createApiForTest(*store_);
    envoy::extensions::filters::http::http_wasm::v3::GuestConfig guest_config;
    const std::string yaml = TestEnvironment::substitute(absl::StrCat(R"EOF(
    max_request_bytes: 5242880
    configuration:
       "@type": "type.googleapis.com/google.protobuf.StringValue"
       value: "some configuration"
    code:
      local:
        filename: "{{ test_rundir }}/test/extensions/filters/http/http_wasm/test_data/req-header/envoy-tests.wasm"
    environment_variables:
      key_values:
        ENVOY_HTTP_WASM_TEST_HEADERS_KEY_VALUE_ENV: bar
      host_env_keys:
        - ENVOY_HTTP_WASM_TEST_HEADERS_HOST_ENV
    )EOF"));

    TestUtility::loadFromYaml(yaml, guest_config);
    guest_config_ = std::make_shared<GuestConfig>(guest_config);
    auto tlsSlotRegistrationCallback = [this](const GuestSharedPtr& loaded_guest_code) {
      guest_and_guest_config_ =
          (getOrCreateThreadLocalInitializedGuest(loaded_guest_code, guest_config_, dispatcher_));
      context_ = std::make_unique<TestFilter>(guest_and_guest_config_->guest(), guest_config_);
      context_->setDecoderFilterCallbacks(decoder_callbacks_);
      context_->setEncoderFilterCallbacks(encoder_callbacks_);
    };
    loadGuestAndSetTlsSlot(guest_config_, scope_, dispatcher_, *api, lifecycle_notifier_,
                           std::move(tlsSlotRegistrationCallback));
  }

protected:
  std::shared_ptr<Guest> guest() { return guest_; }
  std::shared_ptr<Guest> guest_;
  GuestAndGuestConfigSharedPtr guest_and_guest_config_;
  std::unordered_map<std::string, std::string> envs_ = {};

  Stats::SymbolTablePtr symbol_table_;
  std::unique_ptr<Stats::IsolatedStoreImpl> store_;
  Stats::StatNamePool pool_;
  Stats::ScopeSharedPtr scope_;

  NiceMock<Event::MockDispatcher> dispatcher_;
  std::unique_ptr<Context> context_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_callbacks_;
  GuestConfigSharedPtr guest_config_;
  NiceMock<Envoy::StreamInfo::MockStreamInfo> request_stream_info_;
  NiceMock<Server::MockServerLifecycleNotifier> lifecycle_notifier_;
};

TEST_F(WasmHttpFilterTest, HeadersOnlyRequestHeadersWithEnvVars) {
  const std::string host_env_key = "ENVOY_HTTP_WASM_TEST_HEADERS_HOST_ENV";
  const std::string host_env_value = "foo";
  TestEnvironment::setEnvVar(host_env_key, host_env_value, 0);
  setup();
  EXPECT_CALL(encoder_callbacks_, streamInfo()).WillRepeatedly(ReturnRef(request_stream_info_));
  EXPECT_CALL(filter(),
              log_(LogLevel::info, Eq("envs: ENVOY_HTTP_WASM_TEST_HEADERS_HOST_ENV: foo\n"
                                      "ENVOY_HTTP_WASM_TEST_HEADERS_KEY_VALUE_ENV: bar")));

  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks;
  filter().setDecoderFilterCallbacks(decoder_callbacks);

  Http::TestRequestHeaderMapImpl request_headers{
      {":path", "/"}, {"server", "envoy"}, {"testid", "headers only with env vars"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter().decodeHeaders(request_headers, true));
  // this new header is added by the wasm module
  EXPECT_THAT(request_headers.get_("newheader"), Eq("newheadervalue"));
  // this header is overwritten by the wasm module
  EXPECT_THAT(request_headers.get_("server"), Eq("envoy-httpwasm"));
  Http::TestResponseHeaderMapImpl response_headers;
  EXPECT_EQ(filter().encode1xxHeaders(response_headers), Http::Filter1xxHeadersStatus::Continue);
  filter().onDestroy();
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
