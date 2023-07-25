#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>

#include "envoy/access_log/access_log.h"
#include "envoy/buffer/buffer.h"
#include "envoy/extensions/wasm/v3/wasm.pb.validate.h"
#include "envoy/http/filter.h"
#include "envoy/stats/sink.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/common/expr/cel_state.h"
#include "source/extensions/filters/common/expr/evaluator.h"

#include "eval/public/activation.h"

#include "contrib/http_wasm/filters/http/source/host/vm.h"
#include "contrib/http_wasm/filters/http/source/plugin.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

using Host::BufferInterface;
using Host::ContextBase;
using Host::PluginBase;
using Host::PluginHandleBase;
using Host::WasmBase;
using Host::WasmBufferType;
using Host::WasmHandleBase;
using Host::WasmHeaderMapType;
using Host::WasmResult;
using Host::WasmStreamType;

using VmConfig = envoy::extensions::wasm::v3::VmConfig;
using CapabilityRestrictionConfig = envoy::extensions::wasm::v3::CapabilityRestrictionConfig;

class PluginHandle;
class Wasm;

using PluginBaseSharedPtr = std::shared_ptr<PluginBase>;
using PluginHandleBaseSharedPtr = std::shared_ptr<PluginHandleBase>;
using PluginHandleSharedPtr = std::shared_ptr<PluginHandle>;
using WasmHandleBaseSharedPtr = std::shared_ptr<WasmHandleBase>;

class Buffer : public Host::BufferBase {
public:
  Buffer() = default;

  // Host::BufferInterface
  size_t size() const override;
  int64_t copyTo(void* ptr, uint64_t size) override;
  WasmResult copyFrom(size_t start, std::string_view data, size_t length) override;

  // Host::BufferBase
  void clear() override {
    Host::BufferBase::clear();
    const_buffer_instance_ = nullptr;
    buffer_instance_ = nullptr;
  }
  Buffer* set(std::string_view data) { return static_cast<Buffer*>(Host::BufferBase::set(data)); }

  Buffer* set(::Envoy::Buffer::Instance* buffer_instance) {
    clear();
    buffer_instance_ = buffer_instance;
    const_buffer_instance_ = buffer_instance;
    return this;
  }
  Buffer* set(const ::Envoy::Buffer::Instance* buffer_instance) {
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
class Context : public Host::ContextBase,
                public Logger::Loggable<Logger::Id::wasm>,
                public AccessLog::Instance,
                public Http::StreamFilter,
                public Filters::Common::Expr::StreamActivation,
                public std::enable_shared_from_this<Context> {
public:
  Context();                                          // Testing.
  Context(Wasm* wasm);                                // Vm Context.
  Context(Wasm* wasm, const PluginSharedPtr& plugin); // Root Context.
  Context(Wasm* wasm, uint32_t root_context_id,
          PluginHandleSharedPtr plugin_handle); // Stream context.
  ~Context() = default;

  Wasm* wasm() const;
  Plugin* plugin() const;
  Context* rootContext() const;
  Upstream::ClusterManager& clusterManager() const;
  void maybeAddContentLength(uint64_t content_length) override;

  void error(std::string_view message) override;

  // Retrieves the stream info associated with the request (a.k.a active stream).
  // It selects a value based on the following order: encoder callback, decoder
  // callback, log callback, network read filter callback, network write filter
  // callback. As long as any one of the callbacks is invoked, the value should be
  // available.
  const StreamInfo::StreamInfo* getConstRequestStreamInfo() const;
  StreamInfo::StreamInfo* getRequestStreamInfo() const;

  // AccessLog::Instance
  void log(const Http::RequestHeaderMap* request_headers,
           const Http::ResponseHeaderMap* response_headers,
           const Http::ResponseTrailerMap* response_trailers,
           const StreamInfo::StreamInfo& stream_info,
           AccessLog::AccessLogType access_log_type) override;

  uint32_t getLogLevel() override;

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

  // VM calls out to host.
  // Host::ContextBase

  // General
  WasmResult log(uint32_t level, std::string_view message) override;
  std::string_view getConfiguration() override;
  void sendLocalResponse(uint32_t response_code) override;

  // Header/Trailer/Metadata Maps
  WasmResult addHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                               std::string_view value) override;
  WasmResult getHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                               std::string_view* value) override;

  WasmResult removeHeaderMapValue(WasmHeaderMapType type, std::string_view key) override;
  WasmResult replaceHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                   std::string_view value) override;

  WasmResult getHeaderMapSize(WasmHeaderMapType type, uint32_t* size) override;

  // Buffer
  BufferInterface* getBuffer(WasmBufferType type) override;

protected:
  friend class Wasm;
  Http::HeaderMap* getMap(WasmHeaderMapType type);
  const Http::HeaderMap* getConstMap(WasmHeaderMapType type);

  const LocalInfo::LocalInfo* root_local_info_{nullptr}; // set only for root_context.
  PluginHandleSharedPtr plugin_handle_{nullptr};

  // HTTP callbacks.
  Envoy::Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Envoy::Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};

  // HTTP filter state.
  Http::RequestHeaderMap* request_headers_{};
  Http::ResponseHeaderMap* response_headers_{};
  ::Envoy::Buffer::Instance* request_body_buffer_{};
  ::Envoy::Buffer::Instance* response_body_buffer_{};
  Http::RequestTrailerMap* request_trailers_{};
  Http::ResponseTrailerMap* response_trailers_{};
  Http::MetadataMap* request_metadata_{};
  Http::MetadataMap* response_metadata_{};

  // Temporary state.
  Buffer buffer_;
  bool buffering_request_body_ = false;
  bool buffering_response_body_ = false;
  bool end_of_stream_ = false;
};
using ContextSharedPtr = std::shared_ptr<Context>;

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
