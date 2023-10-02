#include "source/extensions/common/http_wasm/context.h"
#include "http_wasm_common.h"
#include "http_wasm_enums.h"
#include "source/extensions/common/http_wasm/guest.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <memory>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/extensions/filters/http/http_wasm/v3/wasm.pb.validate.h"
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
#include "openssl/bytestring.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

#define CHECK_FAIL(_stream_type, _stream_type2, _return_open, _return_closed)                      \
  if (isFailed()) {                                                                                \
    if (initialized_guest_->fail_open_) {                                                          \
      return _return_open;                                                                         \
    }                                                                                              \
    return _return_closed;                                                                         \
  }

#define CHECK_FAIL_HTTP(_return_open, _return_closed)                                              \
  CHECK_FAIL(WasmStreamType::Request, WasmStreamType::Response, _return_open, _return_closed)

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

namespace {
using HashPolicy = envoy::config::route::v3::RouteAction::HashPolicy;
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
  return 0;
}

int64_t Buffer::copyTo(void* ptr, uint64_t dest_size) {
  // if dest_size is 0, do not copy, spec says panic
  uint64_t eof = 1;
  eof = (eof << 32);
  if (!const_buffer_instance_ || bytes_to_skip_ >= const_buffer_instance_->length()) {
    return eof; // panic
  }
  auto data_size = const_buffer_instance_->length();
  uint64_t bytes_to_copy = std::min(dest_size, data_size - bytes_to_skip_);
  const_buffer_instance_->copyOut(bytes_to_skip_, bytes_to_copy, ptr);

  bytes_to_skip_ += dest_size;
  eof = bytes_to_skip_ >= data_size;
  if (eof) {
    bytes_to_skip_ = 0;
    eof = (static_cast<uint64_t>(eof << 32));
  }
  return (uint64_t(bytes_to_copy) | eof);
}

WasmResult Buffer::copyFrom(size_t start, std::string_view data, size_t length) {
  if (buffer_instance_ != nullptr) {
    if (length != 0) {
      buffer_instance_->drain(buffer_instance_->length());
    }
    buffer_instance_->prepend(toAbslStringView(data));
    return WasmResult::Ok;
  }
  return WasmResult::Ok;
}

// Context::Context(Guest* wasm) : guest_(wasm), parent_context_(this) {
//   guest_->contexts_[id_] = this;
// }
// Context::Context(Guest* wasm, const InitializedGuestSharedPtr& initialized_guest)
//     : guest_(wasm), id_(wasm->allocContextId()), root_id_(initialized_guest->name_),
//       root_log_prefix_(initialized_guest->name_), initialized_guest_(initialized_guest) {
//   current_context_ = this;
//   root_local_info_ = &initialized_guest->localInfo();
//   guest_->contexts_[id_] = this;
// }
Context::Context(Guest* wasm, InitializedGuestSharedPtr& initialized_guest)
    // Context::Context(Guest* wasm, InitializedGuestHandleSharedPtr initialized_guest_handle)
    : guest_(wasm), id_(wasm != nullptr ? wasm->allocContextId() : 0),
      initialized_guest_(initialized_guest) {
  if (guest_ != nullptr) {
    guest_->contexts_[id_] = this;
  }
}

bool Context::isFailed() { return (guest_ == nullptr || guest_->isFailed()); }

Runtime* Context::runtime() const { return guest_->runtime(); }
// InitializedGuest* Context::initializedGuest() const { return
// static_cast<InitializedGuest*>(initialized_guest_.get()); } Context* Context::rootContext()
// const { return static_cast<Context*>(root_context()); }
Upstream::ClusterManager& Context::clusterManager() const { return guest()->clusterManager(); }

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
  case WasmHeaderMapType::ResponseHeaders:
    return response_headers_;
  default:
    return nullptr;
  }
}

const Http::HeaderMap* Context::getConstMap(WasmHeaderMapType type) {
  switch (type) {
  case WasmHeaderMapType::RequestHeaders:
    return request_headers_;
  case WasmHeaderMapType::ResponseHeaders:
    return response_headers_;
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
                                      std::vector<std::string_view>& name_values) {
  auto map = getConstMap(type);
  if (!map) {
    // Requested map type is not currently available.
    return WasmResult::BadArgument;
  }
  const Http::LowerCaseString lower_key{std::string(key)};
  const auto entries = map->get(lower_key);
  if (entries.empty()) {
    return WasmResult::NotFound;
  }

  // Create a vector to hold the individual string_view elements
  std::vector<std::string_view> temp_values;
  for (size_t i = 0; i < entries.size(); i++) {
    temp_values.emplace_back(entries[i]->value().getStringView());
  }
  // Set the output vector
  name_values = std::move(temp_values);
  return WasmResult::Ok;
}

WasmResult Context::getHeaderNames(WasmHeaderMapType type, std::vector<std::string_view>& names) {
  auto map = getConstMap(type);
  if (!map) {
    // Requested map type is not currently available.
    return WasmResult::BadArgument;
  }
  // Create a vector to hold the individual string_view elements
  std::vector<std::string_view> keys;

  map->iterate([&keys](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    keys.emplace_back(header.key().getStringView());
    // ENVOY_LOG(warn, "header key: {}", header.key().getStringView());
    return Http::HeaderMap::Iterate::Continue;
  });

  // Set the output vector
  names = std::move(keys);
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
    if (!local_response_headers_) {
      local_response_headers_ =
          Envoy::Http::createHeaderMap<Envoy::Http::ResponseHeaderMapImpl>({});
    }
    local_response_headers_->setCopy(Envoy::Http::LowerCaseString(key),
                                     Envoy::Http::LowerCaseString(value));
    return WasmResult::Ok;
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

Buffer* Context::getBuffer(WasmBufferType type) {
  switch (type) {
  case WasmBufferType::HttpRequestBody:
    return buffer_.set(request_body_buffer_);
  case WasmBufferType::HttpResponseBody:
    if (response_body_buffer_ == nullptr) {
      return nullptr;
    }
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

std::string_view Context::getConfiguration() { return initialized_guest_->configuration_; };

Http::FilterHeadersStatus convertFilterHeadersStatus(FilterHeadersStatus status) {
  switch (status) {
  default:
  case FilterHeadersStatus::Continue:
    return Http::FilterHeadersStatus::Continue;
  case FilterHeadersStatus::StopIteration:
    // return Http::FilterHeadersStatus::StopIteration;
    return Http::FilterHeadersStatus::StopAllIterationAndWatermark;
  }
};

Http::FilterTrailersStatus convertFilterTrailersStatus(FilterTrailersStatus status) {
  switch (status) {
  default:
  case FilterTrailersStatus::Continue:
    return Http::FilterTrailersStatus::Continue;
  case FilterTrailersStatus::StopIteration:
    return Http::FilterTrailersStatus::StopIteration;
  }
};

Http::FilterMetadataStatus convertFilterMetadataStatus(FilterMetadataStatus status) {
  switch (status) {
  default:
  case FilterMetadataStatus::Continue:
    return Http::FilterMetadataStatus::Continue;
  }
};

Http::FilterDataStatus convertFilterDataStatus(FilterDataStatus status) {
  switch (status) {
  default:
  case FilterDataStatus::Continue:
    return Http::FilterDataStatus::Continue;
  case FilterDataStatus::StopIteration:
    return Http::FilterDataStatus::StopIterationNoBuffer;
    // case FilterDataStatus::StopIterationAndWatermark:
    //   return Http::FilterDataStatus::StopIterationAndWatermark;
    // case FilterDataStatus::StopIterationNoBuffer:
    //   return Http::FilterDataStatus::StopIterationNoBuffer;
  }
};

void Context::onDestroy() {
  if (destroyed_ || !in_vm_context_created_) {
    return;
  }
  destroyed_ = true;
}

void Context::sendLocalResponse(WasmBufferType type) {
  if ((type == WasmBufferType::HttpRequestBody) && (local_response_status_code_ == 0)) {
    return;
  }
  if (decoder_callbacks_ && (!local_response_body_.empty() || local_response_status_code_ > 0)) {
    if (local_response_status_code_ == 0) {
      // guest has not set the response code, get the code sent by the upstream
      std::vector<std::string_view> values;
      auto result = getHeaderMapValue(WasmHeaderMapType::ResponseHeaders, ":status", values);
      while (true) {
        if (result != WasmResult::Ok) {
          local_response_status_code_ = 200;
          break;
        }
        if ((!values.empty()) || (values.size() > 1)) {
          local_response_status_code_ = 200;
          break;
        }
        if (values[0].size() > 3) {
          local_response_status_code_ = 200;
          break;
        }
        if (!absl::SimpleAtoi(values[0], &local_response_status_code_)) {
          local_response_status_code_ = 200;
          break;
        }
        break;
      }
    }
    const auto update_headers = [this](Envoy::Http::ResponseHeaderMap& headers) {
      // copy this->response_headers_ to headers
      headers = *this->response_headers_;
      std::vector<std::string_view> names;
      this->getHeaderNames(WasmHeaderMapType::ResponseHeaders, names);
      // iterate over names and print
      for (auto& name : names) {
        std::vector<std::string_view> values;
        this->getHeaderMapValue(WasmHeaderMapType::ResponseHeaders, name, values);
        ENVOY_LOG(warn, "resp-header: {}={}", name, values[0]);
        for (auto& value : values) {
          headers.addCopy(Http::LowerCaseString(std::string(name)), std::string(value));
        }
      }
    };
    decoder_callbacks_->sendLocalReply(static_cast<Envoy::Http::Code>(local_response_status_code_),
                                       local_response_body_, update_headers, 0, "" /*details*/);
    clearLocalResponse();
  }
}

void Context::setLocalResponseCode(uint32_t response_code) {
  local_response_status_code_ = response_code;
}

void Context::setLocalResponseBody(std::string_view body) { local_response_body_ = body; }
Http::FilterHeadersStatus Context::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  in_vm_context_created_ = true;
  request_headers_ = &headers;
  if (!end_stream) {
    // If this is not a header-only request, we will handle request in decodeData.
    return Http::FilterHeadersStatus::StopIteration;
  }
  LocalResponseAfterGuestCall actions(this, WasmBufferType::HttpRequestBody);
  clearLocalResponse();
  end_of_stream_ = end_stream;
  return convertFilterHeadersStatus(onRequestHeaders(headerSize(&headers), end_stream));
}

Http::FilterDataStatus Context::decodeData(::Envoy::Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(warn, " decodeData: endStream: {}", end_stream);
  if (!in_vm_context_created_) {
    return Http::FilterDataStatus::Continue;
  }
  LocalResponseAfterGuestCall actions(this, WasmBufferType::HttpRequestBody);
  clearLocalResponse();
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
  ENVOY_LOG(debug, "encodeHeaders: endStream: {}", end_stream);
  response_headers_ = &headers;
  if (local_response_headers_) {
    local_response_headers_->iterate(
        [this](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
          this->response_headers_->appendCopy(
              Envoy::Http::LowerCaseString(header.key().getStringView()),
              Envoy::Http::LowerCaseString(header.value().getStringView()));
          ENVOY_LOG(warn, "appending resp header key: {}", header.key().getStringView());
          return Http::HeaderMap::Iterate::Continue;
        });
  }

  if (!in_vm_context_created_) {
    return Http::FilterHeadersStatus::Continue;
  }
  if (!end_stream) {
    // If this is not a header-only response, we will handle response in encodeData.
    return Http::FilterHeadersStatus::StopIteration;
  }
  LocalResponseAfterGuestCall actions(this, WasmBufferType::HttpResponseBody);
  end_of_stream_ = end_stream;
  auto result = convertFilterHeadersStatus(onResponseHeaders(headerSize(&headers), end_stream));
  return result;
}

Http::FilterDataStatus Context::encodeData(::Envoy::Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(debug, "encodeData: endStream: {}", end_stream);
  if (!in_vm_context_created_) {
    return Http::FilterDataStatus::Continue;
  }
  LocalResponseAfterGuestCall actions(this, WasmBufferType::HttpResponseBody);
  response_body_buffer_ = &data;
  end_of_stream_ = end_stream;
  const auto buffer = getBuffer(WasmBufferType::HttpResponseBody);
  const auto buffer_size = (buffer == nullptr) ? 0 : buffer->size();
  auto result = convertFilterDataStatus(onResponseBody(buffer_size, end_stream));
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

FilterHeadersStatus Context::convertVmCallResultToFilterHeadersStatus(uint64_t result) {
  return static_cast<FilterHeadersStatus>(result);
}

FilterDataStatus Context::convertVmCallResultToFilterDataStatus(uint64_t result) {
  return static_cast<FilterDataStatus>(result);
}

// FilterTrailersStatus Context::convertVmCallResultToFilterTrailersStatus(uint64_t result) {
//   return static_cast<FilterTrailersStatus>(result);
// }

// FilterMetadataStatus Context::convertVmCallResultToFilterMetadataStatus(uint64_t result) {
//   if (static_cast<FilterMetadataStatus>(result) == FilterMetadataStatus::Continue) {
//     return FilterMetadataStatus::Continue;
//   }
//   return FilterMetadataStatus::Continue; // This is currently the only return code.
// }

Context::~Context() {
  // Do not remove vm context which has the same lifetime as guest_.
  if (id_ != 0U) {
    guest_->contexts_.erase(id_);
  }
}

FilterHeadersStatus Context::onRequestHeaders(uint32_t headers, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopIteration);
  const auto result = guest_->handle_request_(this);
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopIteration);
  request_context_ = uint32_t(result >> 32);
  uint32_t next = uint32_t(result);
  ENVOY_LOG(debug, "onRequestHeaders: {} {} {}", request_context_, next, end_of_stream);
  return convertVmCallResultToFilterHeadersStatus(next);
}

FilterDataStatus Context::onRequestBody(uint32_t body_length, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIteration);
  const auto result = guest_->handle_request_(this);
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIteration);
  request_context_ = uint32_t(result >> 32);
  uint32_t next = uint32_t(result);
  return convertVmCallResultToFilterDataStatus(next);
}

FilterTrailersStatus Context::onRequestTrailers(uint32_t trailers) {
  CHECK_FAIL_HTTP(FilterTrailersStatus::Continue, FilterTrailersStatus::StopIteration);
  return FilterTrailersStatus::Continue;
}

FilterMetadataStatus Context::onRequestMetadata(uint32_t elements) {
  CHECK_FAIL_HTTP(FilterMetadataStatus::Continue, FilterMetadataStatus::Continue);
  return FilterMetadataStatus::Continue;
}

FilterHeadersStatus Context::onResponseHeaders(uint32_t headers, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopIteration);
  ENVOY_LOG(debug, "onResponseHeaders: {} ", request_context_);
  guest_->handle_response_(this, request_context_, 0);
  return FilterHeadersStatus::Continue;
}

FilterDataStatus Context::onResponseBody(uint32_t body_length, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIteration);
  guest_->handle_response_(this, request_context_, 0);
  return FilterDataStatus::Continue;
}

FilterTrailersStatus Context::onResponseTrailers(uint32_t trailers) {
  CHECK_FAIL_HTTP(FilterTrailersStatus::Continue, FilterTrailersStatus::StopIteration);
  return FilterTrailersStatus::Continue;
}

FilterMetadataStatus Context::onResponseMetadata(uint32_t elements) {
  CHECK_FAIL_HTTP(FilterMetadataStatus::Continue, FilterMetadataStatus::Continue);
  return FilterMetadataStatus::Continue;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
