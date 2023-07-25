#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/vm.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <memory>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/extensions/wasm/v3/wasm.pb.validate.h"
#include "envoy/grpc/status.h"
#include "envoy/http/codes.h"
#include "envoy/local_info/local_info.h"
#include "envoy/network/filter.h"
#include "envoy/stats/sink.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/logger.h"
#include "source/common/common/safe_memcpy.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/message_impl.h"
#include "source/common/http/utility.h"
#include "source/common/tracing/http_tracer_impl.h"
#include "source/extensions/filters/common/expr/context.h"

#include "absl/base/casts.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/node_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "eval/public/cel_value.h"
#include "eval/public/containers/field_access.h"
#include "eval/public/containers/field_backed_list_impl.h"
#include "eval/public/containers/field_backed_map_impl.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#include "include/proxy-wasm/pairs_util.h"
#include "openssl/bytestring.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
using Host::DeferAfterCallActions;
using Host::LogLevel;
using Host::Word;

namespace {

// FilterState prefix for CelState values.
constexpr absl::string_view CelStateKeyPrefix = "httpwasm.";

using HashPolicy = envoy::config::route::v3::RouteAction::HashPolicy;
using CelState = Filters::Common::Expr::CelState;
using CelStatePrototype = Filters::Common::Expr::CelStatePrototype;

template <typename P> static uint32_t headerSize(const P& p) { return p ? p->size() : 0; }

Upstream::HostDescriptionConstSharedPtr getHost(const StreamInfo::StreamInfo* info) {
  if (info && info->upstreamInfo() && info->upstreamInfo().value().get().upstreamHost()) {
    return info->upstreamInfo().value().get().upstreamHost();
  }
  return nullptr;
}

} // namespace

size_t Buffer::size() const {
  if (const_buffer_instance_) {
    return const_buffer_instance_->length();
  }
  return Host::BufferBase::size();
}

int64_t Buffer::copyTo(void* ptr, uint64_t dest_size) {
  // if dest_size is 0, do not copy, spec says panic
  uint64_t eof = 1;
  eof = (eof << 32);
  if (!const_buffer_instance_) {
    return eof; // panic
  }
  auto data_size = const_buffer_instance_->length();
  uint64_t bytes_to_copy = std::min(dest_size, data_size - bytes_to_skip_);
  const_buffer_instance_->copyOut(bytes_to_skip_, bytes_to_copy, ptr);
  bytes_to_skip_ += dest_size;
  eof = (static_cast<uint64_t>(bytes_to_copy < dest_size ? 1 : 0) << 32);
  return (uint64_t(bytes_to_copy) | eof);
}

WasmResult Buffer::copyFrom(size_t start, std::string_view data, size_t length) {
  if (buffer_instance_) {
    if (length != 0) {
      buffer_instance_->drain(buffer_instance_->length());
    }
    buffer_instance_->prepend(toAbslStringView(data));
    return WasmResult::Ok;
  }
}

Context::Context() = default;
Context::Context(Wasm* wasm) : ContextBase(wasm) {}
Context::Context(Wasm* wasm, const PluginSharedPtr& plugin) : ContextBase(wasm, plugin) {
  root_local_info_ = &std::static_pointer_cast<Plugin>(plugin)->localInfo();
}
Context::Context(Wasm* wasm, uint32_t root_context_id, PluginHandleSharedPtr plugin_handle)
    : ContextBase(wasm, root_context_id, plugin_handle), plugin_handle_(plugin_handle) {}

Wasm* Context::wasm() const { return static_cast<Wasm*>(wasm_); }
Plugin* Context::plugin() const { return static_cast<Plugin*>(plugin_.get()); }
Context* Context::rootContext() const { return static_cast<Context*>(root_context()); }
Upstream::ClusterManager& Context::clusterManager() const { return wasm()->clusterManager(); }

void Context::error(std::string_view message) { ENVOY_LOG(trace, message); }

template <typename I> inline uint32_t align(uint32_t i) {
  return (i + sizeof(I) - 1) & ~(sizeof(I) - 1);
}

template <typename I> inline char* align(char* p) {
  return reinterpret_cast<char*>((reinterpret_cast<uintptr_t>(p) + sizeof(I) - 1) &
                                 ~(sizeof(I) - 1));
}

// Header/Trailer/Metadata Maps.
Http::HeaderMap* Context::getMap(WasmHeaderMapType type) {
  switch (type) {
  case WasmHeaderMapType::RequestHeaders:
    return request_headers_;
  case WasmHeaderMapType::RequestTrailers:
    if (request_trailers_ == nullptr && request_body_buffer_ && end_of_stream_ &&
        decoder_callbacks_) {
      request_trailers_ = &decoder_callbacks_->addDecodedTrailers();
    }
    return request_trailers_;
  case WasmHeaderMapType::ResponseHeaders:
    return response_headers_;
  case WasmHeaderMapType::ResponseTrailers:
    if (response_trailers_ == nullptr && response_body_buffer_ && end_of_stream_ &&
        encoder_callbacks_) {
      response_trailers_ = &encoder_callbacks_->addEncodedTrailers();
    }
    return response_trailers_;
  default:
    return nullptr;
  }
}

const Http::HeaderMap* Context::getConstMap(WasmHeaderMapType type) {
  switch (type) {
  case WasmHeaderMapType::RequestHeaders:
    return request_headers_;
  case WasmHeaderMapType::RequestTrailers:
    return request_trailers_;
  case WasmHeaderMapType::ResponseHeaders:
    return response_headers_;
  case WasmHeaderMapType::ResponseTrailers:
    return response_trailers_;
  }
  IS_ENVOY_BUG("unexpected");
  return nullptr;
}

WasmResult Context::addHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                      std::string_view value) {
  auto map = getMap(type);
  if (!map) {
    return WasmResult::BadArgument;
  }
  const Http::LowerCaseString lower_key{std::string(key)};
  map->addCopy(lower_key, std::string(value));
  if (type == WasmHeaderMapType::RequestHeaders && decoder_callbacks_) {
    decoder_callbacks_->downstreamCallbacks()->clearRouteCache();
  }
  return WasmResult::Ok;
}

WasmResult Context::getHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                      std::string_view* value) {
  auto map = getConstMap(type);
  if (!map) {
    // Requested map type is not currently available.
    return WasmResult::BadArgument;
  }
  const Http::LowerCaseString lower_key{std::string(key)};
  const auto entry = map->get(lower_key);
  if (entry.empty()) {
    return WasmResult::NotFound;
  }
  *value = toStdStringView(entry[0]->value().getStringView());
  return WasmResult::Ok;
}

WasmResult Context::removeHeaderMapValue(WasmHeaderMapType type, std::string_view key) {
  auto map = getMap(type);
  if (!map) {
    return WasmResult::BadArgument;
  }
  const Http::LowerCaseString lower_key{std::string(key)};
  map->remove(lower_key);
  if (type == WasmHeaderMapType::RequestHeaders && decoder_callbacks_) {
    decoder_callbacks_->downstreamCallbacks()->clearRouteCache();
  }
  return WasmResult::Ok;
}

WasmResult Context::replaceHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                          std::string_view value) {
  auto map = getMap(type);
  if (!map) {
    return WasmResult::BadArgument;
  }
  const Http::LowerCaseString lower_key{std::string(key)};
  map->setCopy(lower_key, toAbslStringView(value));
  if (type == WasmHeaderMapType::RequestHeaders && decoder_callbacks_) {
    decoder_callbacks_->downstreamCallbacks()->clearRouteCache();
  }
  return WasmResult::Ok;
}

WasmResult Context::getHeaderMapSize(WasmHeaderMapType type, uint32_t* result) {
  auto map = getMap(type);
  if (!map) {
    return WasmResult::BadArgument;
  }
  *result = map->byteSize();
  return WasmResult::Ok;
}

// Buffer

BufferInterface* Context::getBuffer(WasmBufferType type) {
  switch (type) {
  case WasmBufferType::HttpRequestBody:
    return buffer_.set(request_body_buffer_);
  case WasmBufferType::HttpResponseBody:
    return buffer_.set(response_body_buffer_);
  default:
    return nullptr;
  }
}

// StreamInfo
const StreamInfo::StreamInfo* Context::getConstRequestStreamInfo() const {
  if (encoder_callbacks_) {
    return &encoder_callbacks_->streamInfo();
  } else if (decoder_callbacks_) {
    return &decoder_callbacks_->streamInfo();
  }
  return nullptr;
}

WasmResult Context::log(uint32_t level, std::string_view message) {
  switch (static_cast<LogLevel>(level)) {
  case LogLevel::debug:
    ENVOY_LOG(debug, "httpwasm log{}: {}", log_prefix(), message);
    return WasmResult::Ok;
  case LogLevel::info:
    ENVOY_LOG(info, "httpwasm log{}: {}", log_prefix(), message);
    return WasmResult::Ok;
  case LogLevel::warn:
    ENVOY_LOG(warn, "wasm log{}: {}", log_prefix(), message);
    return WasmResult::Ok;
  case LogLevel::error:
    ENVOY_LOG(error, "wasm log{}: {}", log_prefix(), message);
    return WasmResult::Ok;
  case LogLevel::none:
    return WasmResult::Ok;
  default:
    PANIC("not implemented");
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

uint32_t Context::getLogLevel() {
  // Like the "log" call above, assume that spdlog level as an int
  // matches the enum in the SDK
  return static_cast<uint32_t>(ENVOY_LOGGER().level());
}

std::string_view Context::getConfiguration() { return plugin_->plugin_configuration_; };

Http::FilterHeadersStatus convertFilterHeadersStatus(Host::FilterHeadersStatus status) {
  switch (status) {
  default:
  case Host::FilterHeadersStatus::Continue:
    return Http::FilterHeadersStatus::Continue;
  case Host::FilterHeadersStatus::StopIteration:
    return Http::FilterHeadersStatus::StopIteration;
  case Host::FilterHeadersStatus::StopAllIterationAndBuffer:
    return Http::FilterHeadersStatus::StopAllIterationAndBuffer;
  case Host::FilterHeadersStatus::StopAllIterationAndWatermark:
    return Http::FilterHeadersStatus::StopAllIterationAndWatermark;
  }
};

Http::FilterTrailersStatus convertFilterTrailersStatus(Host::FilterTrailersStatus status) {
  switch (status) {
  default:
  case Host::FilterTrailersStatus::Continue:
    return Http::FilterTrailersStatus::Continue;
  case Host::FilterTrailersStatus::StopIteration:
    return Http::FilterTrailersStatus::StopIteration;
  }
};

Http::FilterMetadataStatus convertFilterMetadataStatus(Host::FilterMetadataStatus status) {
  switch (status) {
  default:
  case Host::FilterMetadataStatus::Continue:
    return Http::FilterMetadataStatus::Continue;
  }
};

Http::FilterDataStatus convertFilterDataStatus(Host::FilterDataStatus status) {
  switch (status) {
  default:
  case Host::FilterDataStatus::Continue:
    return Http::FilterDataStatus::Continue;
  case Host::FilterDataStatus::StopIterationAndBuffer:
    return Http::FilterDataStatus::StopIterationAndBuffer;
  case Host::FilterDataStatus::StopIterationAndWatermark:
    return Http::FilterDataStatus::StopIterationAndWatermark;
  case Host::FilterDataStatus::StopIterationNoBuffer:
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
};

void Context::log(const Http::RequestHeaderMap* request_headers,
                  const Http::ResponseHeaderMap* response_headers,
                  const Http::ResponseTrailerMap* response_trailers,
                  const StreamInfo::StreamInfo& stream_info, AccessLog::AccessLogType) {
  // `log` may be called multiple times due to mid-request logging -- we only want to run on the
  // last call.
  if (!stream_info.requestComplete().has_value()) {
    return;
  }
  if (!in_vm_context_created_) {
    // If the request is invalid then onRequestHeaders() will not be called and neither will
    // onCreate() in cases like sendLocalReply who short-circuits envoy
    // lifecycle. This is because Envoy does not have a well defined lifetime for the combined
    // HTTP
    // + AccessLog filter. Thus, to log these scenarios, we call onCreate() in log function below.
    onCreate();
  }
}

void Context::onDestroy() {
  if (destroyed_ || !in_vm_context_created_) {
    return;
  }
  destroyed_ = true;
  onDone();
  onDelete();
}

void Context::sendLocalResponse(uint32_t response_code) {
  if (decoder_callbacks_) {
    addAfterVmCallAction([this, response_code] {
      decoder_callbacks_->sendLocalReply(static_cast<Envoy::Http::Code>(response_code),
                                         "" /*body_text*/, nullptr, 0, "" /*details*/);
    });
  }
}

Http::FilterHeadersStatus Context::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  ENVOY_LOG(warn, " decodeHeaders: endStream: {}", end_stream);
  onCreate();
  request_headers_ = &headers;
  if (!end_stream) {
    // If this is not a header-only request, we will handle request in decodeData.
    return Http::FilterHeadersStatus::StopIteration;
  }
  end_of_stream_ = end_stream;
  auto result = convertFilterHeadersStatus(onRequestHeaders(headerSize(&headers), end_stream));

  return result;
}

Http::FilterDataStatus Context::decodeData(::Envoy::Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(warn, " decodeData: endStream: {}", end_stream);
  if (!in_vm_context_created_) {
    return Http::FilterDataStatus::Continue;
  }
  DeferAfterCallActions actions(this);
  request_body_buffer_ = &data;
  end_of_stream_ = end_stream;
  const auto buffer = getBuffer(WasmBufferType::HttpRequestBody);
  const auto buffer_size = (buffer == nullptr) ? 0 : buffer->size();
  buffering_request_body_ = true;
  auto result = convertFilterDataStatus(onRequestBody(buffer_size, end_stream));
  return result;
}

Http::FilterTrailersStatus Context::decodeTrailers(Http::RequestTrailerMap& trailers) {
  if (!in_vm_context_created_) {
    return Http::FilterTrailersStatus::Continue;
  }
  request_trailers_ = &trailers;
  auto result = convertFilterTrailersStatus(onRequestTrailers(headerSize(&trailers)));
  if (result == Http::FilterTrailersStatus::Continue) {
    request_trailers_ = nullptr;
  }
  return result;
}

Http::FilterMetadataStatus Context::decodeMetadata(Http::MetadataMap& request_metadata) {
  if (!in_vm_context_created_) {
    return Http::FilterMetadataStatus::Continue;
  }
  request_metadata_ = &request_metadata;
  auto result = convertFilterMetadataStatus(onRequestMetadata(headerSize(&request_metadata)));
  if (result == Http::FilterMetadataStatus::Continue) {
    request_metadata_ = nullptr;
  }
  return result;
}

void Context::setDecoderFilterCallbacks(Envoy::Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

Http::Filter1xxHeadersStatus Context::encode1xxHeaders(Http::ResponseHeaderMap&) {
  return Http::Filter1xxHeadersStatus::Continue;
}

Http::FilterHeadersStatus Context::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                 bool end_stream) {
  if (!in_vm_context_created_) {
    return Http::FilterHeadersStatus::Continue;
  }
  response_headers_ = &headers;
  end_of_stream_ = end_stream;
  auto result = convertFilterHeadersStatus(onResponseHeaders(headerSize(&headers), end_stream));
  if (result == Http::FilterHeadersStatus::Continue) {
    response_headers_ = nullptr;
  }
  return result;
}

Http::FilterDataStatus Context::encodeData(::Envoy::Buffer::Instance& data, bool end_stream) {
  if (!in_vm_context_created_) {
    return Http::FilterDataStatus::Continue;
  }
  response_body_buffer_ = &data;
  end_of_stream_ = end_stream;
  const auto buffer = getBuffer(WasmBufferType::HttpResponseBody);
  const auto buffer_size = (buffer == nullptr) ? 0 : buffer->size();
  auto result = convertFilterDataStatus(onResponseBody(buffer_size, end_stream));
  buffering_response_body_ = false;
  switch (result) {
  case Http::FilterDataStatus::Continue:
    request_body_buffer_ = nullptr;
    break;
  case Http::FilterDataStatus::StopIterationAndBuffer:
    buffering_response_body_ = true;
    break;
  case Http::FilterDataStatus::StopIterationAndWatermark:
  case Http::FilterDataStatus::StopIterationNoBuffer:
    break;
  }
  return result;
}

Http::FilterTrailersStatus Context::encodeTrailers(Http::ResponseTrailerMap& trailers) {
  if (!in_vm_context_created_) {
    return Http::FilterTrailersStatus::Continue;
  }
  response_trailers_ = &trailers;
  auto result = convertFilterTrailersStatus(onResponseTrailers(headerSize(&trailers)));
  if (result == Http::FilterTrailersStatus::Continue) {
    response_trailers_ = nullptr;
  }
  return result;
}

Http::FilterMetadataStatus Context::encodeMetadata(Http::MetadataMap& response_metadata) {
  if (!in_vm_context_created_) {
    return Http::FilterMetadataStatus::Continue;
  }
  response_metadata_ = &response_metadata;
  auto result = convertFilterMetadataStatus(onResponseMetadata(headerSize(&response_metadata)));
  if (result == Http::FilterMetadataStatus::Continue) {
    response_metadata_ = nullptr;
  }
  return result;
}

void Context::setEncoderFilterCallbacks(Envoy::Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

void Context::maybeAddContentLength(uint64_t content_length) {
  if (request_headers_ != nullptr) {
    request_headers_->setContentLength(content_length);
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
