#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string_view>

#include "envoy/access_log/access_log.h"
#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"
#include "envoy/stats/sink.h"
#include "guest.h"
#include "source/common/buffer/buffer_impl.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

#include "source/extensions/common/http_wasm/guest.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"
#include "source/extensions/common/http_wasm/http_wasm_common.h"
#include "source/extensions/common/http_wasm/guest_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class GuestConfigHandle;
class GuestConfig;
class Guest;
class GuestHandle;

using GuestConfigSharedPtr = std::shared_ptr<GuestConfig>;
using GuestConfigHandleSharedPtr = std::shared_ptr<GuestConfigHandle>;
using GuestHandleSharedPtr = std::shared_ptr<GuestHandle>;

class WasmBuffer {
public:
  WasmBuffer() = default;

  size_t size() const;
  int64_t copyTo(void* ptr, uint64_t size);
  WasmResult copyFrom(std::string_view data, size_t length);

  void clear() {
    const_buffer_instance_ = nullptr;
    buffer_instance_ = nullptr;
  }

  WasmBuffer* set(::Envoy::Buffer::Instance* buffer_instance) {
    clear();
    buffer_instance_ = buffer_instance;
    const_buffer_instance_ = buffer_instance;
    return this;
  }
  WasmBuffer* set(Buffer::OwnedImpl* buffer_instance) {
    clear();
    buffer_instance_ = buffer_instance;
    const_buffer_instance_ = buffer_instance;
    return this;
  }
  WasmBuffer* set(const ::Envoy::Buffer::Instance* buffer_instance) {
    clear();
    const_buffer_instance_ = buffer_instance;
    return this;
  }

private:
  const ::Envoy::Buffer::Instance* const_buffer_instance_{};
  ::Envoy::Buffer::Instance* buffer_instance_{};
  uint64_t bytes_to_skip_ = 0;
};

// A context which will be the target of callbacks for a particular session
// e.g. a handler of a stream.
class Context : public Logger::Loggable<Logger::Id::wasm>,
                public Http::StreamFilter,
                public std::enable_shared_from_this<Context> {
public:
  Context(std::shared_ptr<Guest> guest, GuestConfigSharedPtr& initialized_guest);
  Context(Guest* guest, GuestConfigSharedPtr& initialized_guest);

  ~Context() override;

  Guest* guest() const {
    if (guest_ != nullptr) {
      return guest_;
    }
    return guest_shared_.get();
  }

  Upstream::ClusterManager& clusterManager() const;
  void maybeAddContentLength(uint64_t content_length);
  Runtime* runtime() const;

  void error(std::string_view message);

  // Retrieves the stream info associated with the request (a.k.a active stream).
  // It selects a value based on the following order: encoder callback, decoder
  // callback, log callback, network read filter callback, network write filter
  // callback. As long as any one of the callbacks is invoked, the value should be
  // available.

  uint32_t getLogLevel();

  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(::Envoy::Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  Http::FilterMetadataStatus decodeMetadata(Http::MetadataMap& metadata_map) override;
  void setDecoderFilterCallbacks(Envoy::Http::StreamDecoderFilterCallbacks& callbacks) override;

  // Http::StreamEncoderFilter
  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override;
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(::Envoy::Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap& metadata_map) override;
  void setEncoderFilterCallbacks(Envoy::Http::StreamEncoderFilterCallbacks& callbacks) override;

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream);
  FilterDataStatus onRequestBody();
  FilterTrailersStatus onRequestTrailers(uint32_t trailers);
  FilterMetadataStatus onRequestMetadata(uint32_t elements);
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream);
  FilterDataStatus onResponseBody(uint32_t body_length, bool end_of_stream);
  FilterTrailersStatus onResponseTrailers(uint32_t trailers);
  FilterMetadataStatus onResponseMetadata(uint32_t elements);

  bool isFailed();

  // General
  // virtual log
  virtual WasmResult log(int32_t level, std::string_view message);
  std::string_view getConfiguration();
  void sendLocalResponse(WasmBufferType);
  void setLocalResponseCode(uint32_t);
  void setLocalResponseBody(std::string_view);
  void clearLocalResponse() {
    local_response_body_ = "";
    local_response_status_code_ = 0;
    local_response_headers_.reset();
  }

  // Header/Trailer/Metadata Maps
  WasmResult addHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                               std::string_view value);
  WasmResult getHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                               std::vector<std::string_view>& name_values);
  WasmResult getHeaderNames(WasmHeaderMapType type, std::vector<std::string_view>& names);
  WasmResult removeHeaderMapValue(WasmHeaderMapType type, std::string_view key);
  WasmResult replaceHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                   std::string_view value);

  WasmResult getHeaderMapSize(WasmHeaderMapType type, uint32_t* size);

  // Buffer
  WasmBuffer* getBuffer(WasmBufferType type);

  uint64_t getCurrentTimeNanoseconds();
  uint64_t getMonotonicTimeNanoseconds();

  void setFeatureBufferRequest() { guest_feature_set_ = guest_feature_set_ | 0b1; }
  void setFeatureBufferResponse() { guest_feature_set_ = guest_feature_set_ | 0b10; }
  uint8_t getGuestFeatureSet() { return guest_feature_set_; }
  void overwriteRequestBody(std::string_view data, size_t length);

  bool endOfStream() { return end_of_stream_; }

protected:
  friend class Guest;
  Http::HeaderMap* getMap(WasmHeaderMapType type);
  const Http::HeaderMap* getConstMap(WasmHeaderMapType type);

  GuestConfigHandleSharedPtr guest_config_handle_{nullptr};

  // HTTP callbacks.
  Envoy::Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Envoy::Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};

  // HTTP filter state.
  Http::RequestHeaderMap* request_headers_{};
  Http::ResponseHeaderMap* response_headers_{};
  ::Envoy::Buffer::Instance* request_body_buffer_{};
  Buffer::OwnedImpl request_buffer_;
  ::Envoy::Buffer::Instance* response_body_buffer_{};
  Http::RequestTrailerMap* request_trailers_{};
  Http::ResponseTrailerMap* response_trailers_{};
  Http::MetadataMap* request_metadata_{};
  Http::MetadataMap* response_metadata_{};

  // Temporary state.
  WasmBuffer buffer_;
  bool end_of_stream_ = false;

  Guest* guest_ = nullptr;
  std::shared_ptr<Guest> guest_shared_ = nullptr;
  uint32_t id_{0};
  std::shared_ptr<GuestConfig> guest_config_; // set in stream contexts.
  bool destroyed_ = false;
  bool stream_failed_ = false; // Set true after failStream is called in case of VM failure.

private:
  uint8_t guest_feature_set_{0};
  std::string_view local_response_body_;
  uint32_t local_response_status_code_;
  Envoy::Http::ResponseHeaderMapPtr local_response_headers_;
  // helper functions
  FilterHeadersStatus convertVmCallResultToFilterHeadersStatus(uint64_t result);
  FilterDataStatus convertVmCallResultToFilterDataStatus(uint64_t result);

  // request_context_ holds the context id received from the guest as return value of
  // handle_request() call. It is used to identify the context in the callbacks from the guest.
  uint32_t request_context_{0};
};
using ContextSharedPtr = std::shared_ptr<Context>;

class LocalResponseAfterGuestCall {
public:
  LocalResponseAfterGuestCall(Context* context, WasmBufferType type)
      : context_(context), type_(type) {}
  ~LocalResponseAfterGuestCall() { context_->sendLocalResponse(type_); }

private:
  Context* const context_;
  WasmBufferType type_;
};

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
