#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include "contrib/http_wasm/filters/http/source/host/context.h"
#include "contrib/http_wasm/filters/http/source/host/vm.h"

#define CHECK_FAIL(_stream_type, _stream_type2, _return_open, _return_closed)                      \
  if (isFailed()) {                                                                                \
    if (plugin_->fail_open_) {                                                                     \
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
namespace Host {
DeferAfterCallActions::~DeferAfterCallActions() { context_->doAfterVmCallActions(); }

int64_t BufferBase::copyTo(void*, uint64_t) { return 0; }

std::string PluginBase::makeLogPrefix() const {
  std::string prefix;
  if (!name_.empty()) {
    prefix = prefix + " " + name_;
  }
  if (!root_id_.empty()) {
    prefix = prefix + " " + std::string(root_id_);
  }
  if (!vm_id_.empty()) {
    prefix = prefix + " " + std::string(vm_id_);
  }
  return prefix;
}

ContextBase::ContextBase() : parent_context_(this) {}

ContextBase::ContextBase(WasmBase* wasm) : wasm_(wasm), parent_context_(this) {
  wasm_->contexts_[id_] = this;
}

ContextBase::ContextBase(WasmBase* wasm, const std::shared_ptr<PluginBase>& plugin)
    : wasm_(wasm), id_(wasm->allocContextId()), parent_context_(this), root_id_(plugin->root_id_),
      root_log_prefix_(makeRootLogPrefix(plugin->vm_id_)), plugin_(plugin) {
  wasm_->contexts_[id_] = this;
}

ContextBase::ContextBase(WasmBase* wasm, uint32_t parent_context_id,
                         const std::shared_ptr<PluginHandleBase>& plugin_handle)
    : wasm_(wasm), id_(wasm != nullptr ? wasm->allocContextId() : 0),
      parent_context_id_(parent_context_id), plugin_(plugin_handle->plugin()),
      plugin_handle_(plugin_handle) {
  if (wasm_ != nullptr) {
    wasm_->contexts_[id_] = this;
    parent_context_ = wasm_->contexts_[parent_context_id_];
  }
}

WasmVm* ContextBase::wasmVm() const { return wasm_->wasm_vm(); }

bool ContextBase::isFailed() { return (wasm_ == nullptr || wasm_->isFailed()); }

std::string ContextBase::makeRootLogPrefix(std::string_view vm_id) const {
  std::string prefix;
  if (!root_id_.empty()) {
    prefix = prefix + " " + std::string(root_id_);
  }
  if (!vm_id.empty()) {
    prefix = prefix + " " + std::string(vm_id);
  }
  return prefix;
}

bool ContextBase::onStart(std::shared_ptr<PluginBase>) {
  current_context_ = this;
  return true;
}

void ContextBase::onCreate() {
  // NB: If no on_context_create function is registered the in-VM SDK is responsible for
  // managing any required in-VM state.
  in_vm_context_created_ = true;
}

void ContextBase::destroy() {
  if (destroyed_) {
    return;
  }
  destroyed_ = true;
  onDone();
}

// Empty headers/trailers have zero size.
template <typename P> static uint32_t headerSize(const P& p) { return p ? p->size() : 0; }

FilterHeadersStatus ContextBase::onRequestHeaders(uint32_t headers, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopAllIterationAndWatermark);
  const auto result = wasm_->handle_request_(this);
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopAllIterationAndWatermark);
  return convertVmCallResultToFilterHeadersStatus(result);
}

FilterDataStatus ContextBase::onRequestBody(uint32_t body_length, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIterationNoBuffer);
  const auto result = wasm_->handle_request_(this);
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIterationNoBuffer);
  auto ctx = result >> 32;
  uint32_t next = uint32_t(result);
  return convertVmCallResultToFilterDataStatus(next);
}

FilterTrailersStatus ContextBase::onRequestTrailers(uint32_t trailers) {
  CHECK_FAIL_HTTP(FilterTrailersStatus::Continue, FilterTrailersStatus::StopIteration);
  return FilterTrailersStatus::Continue;
}

FilterMetadataStatus ContextBase::onRequestMetadata(uint32_t elements) {
  CHECK_FAIL_HTTP(FilterMetadataStatus::Continue, FilterMetadataStatus::Continue);
  return FilterMetadataStatus::Continue;
}

FilterHeadersStatus ContextBase::onResponseHeaders(uint32_t headers, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterHeadersStatus::Continue, FilterHeadersStatus::StopAllIterationAndWatermark);
  return FilterHeadersStatus::Continue;
}

FilterDataStatus ContextBase::onResponseBody(uint32_t body_length, bool end_of_stream) {
  CHECK_FAIL_HTTP(FilterDataStatus::Continue, FilterDataStatus::StopIterationNoBuffer);
  return FilterDataStatus::Continue;
}

FilterTrailersStatus ContextBase::onResponseTrailers(uint32_t trailers) {
  CHECK_FAIL_HTTP(FilterTrailersStatus::Continue, FilterTrailersStatus::StopIteration);
  return FilterTrailersStatus::Continue;
}

FilterMetadataStatus ContextBase::onResponseMetadata(uint32_t elements) {
  CHECK_FAIL_HTTP(FilterMetadataStatus::Continue, FilterMetadataStatus::Continue);
  return FilterMetadataStatus::Continue;
}

bool ContextBase::onDone() {
  // TODO
  return true;
}

void ContextBase::onLog() {
  // TODO
}

void ContextBase::onDelete() {
  // TODO
}

FilterHeadersStatus ContextBase::convertVmCallResultToFilterHeadersStatus(uint64_t result) {
  if (result == static_cast<uint64_t>(FilterHeadersStatus::StopIteration)) {
    // Always convert StopIteration (pause processing headers, but continue processing body)
    // to StopAllIterationAndWatermark (pause all processing), since the former breaks all
    // assumptions about HTTP processing.
    return FilterHeadersStatus::StopAllIterationAndWatermark;
  }
  return static_cast<FilterHeadersStatus>(result);
}

FilterDataStatus ContextBase::convertVmCallResultToFilterDataStatus(uint64_t result) {
  return static_cast<FilterDataStatus>(result);
}

FilterTrailersStatus ContextBase::convertVmCallResultToFilterTrailersStatus(uint64_t result) {
  return static_cast<FilterTrailersStatus>(result);
}

FilterMetadataStatus ContextBase::convertVmCallResultToFilterMetadataStatus(uint64_t result) {
  if (static_cast<FilterMetadataStatus>(result) == FilterMetadataStatus::Continue) {
    return FilterMetadataStatus::Continue;
  }
  return FilterMetadataStatus::Continue; // This is currently the only return code.
}

ContextBase::~ContextBase() {
  // Do not remove vm context which has the same lifetime as wasm_.
  if (id_ != 0U) {
    wasm_->contexts_.erase(id_);
  }
}

} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
