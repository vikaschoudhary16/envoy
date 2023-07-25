#pragma once

#include <atomic>
#include <chrono>
#include <ctime>
#include <functional>
#include <iostream>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "contrib/http_wasm/filters/http/source/host/context_interface.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace Host {

#include "contrib/http_wasm/filters/http/source/host/http_wasm_common.h"
#include "contrib/http_wasm/filters/http/source/host/http_wasm_enums.h"
class PluginHandleBase;
class WasmBase;
class WasmVm;

/**
 * PluginBase is container to hold plugin information which is shared with all Context(s) created
 * for a given plugin. Embedders may extend this class with additional host-specific plugin
 * information as required.
 * @param name is the name of the plugin.
 * @param root_id is an identifier for the in VM handlers for this plugin.
 * @param vm_id is a string used to differentiate VMs with the same code and VM configuration.
 * @param plugin_configuration is configuration for this plugin.
 * @param fail_open if true the plugin will pass traffic as opposed to close all streams.
 * @param key is used to uniquely identify this plugin instance.
 */
struct PluginBase {
  PluginBase(std::string_view name, std::string_view root_id, std::string_view vm_id,
             std::string_view engine, std::string_view plugin_configuration, bool fail_open,
             std::string_view key)
      : name_(std::string(name)), root_id_(std::string(root_id)), vm_id_(std::string(vm_id)),
        engine_(std::string(engine)), plugin_configuration_(plugin_configuration),
        fail_open_(fail_open),
        key_(root_id_ + "||" + plugin_configuration_ + "||" + std::string(key)),
        log_prefix_(makeLogPrefix()) {}

  const std::string name_;
  const std::string root_id_;
  const std::string vm_id_;
  const std::string engine_;
  const std::string plugin_configuration_;
  const bool fail_open_;

  const std::string& key() const { return key_; }
  const std::string& log_prefix() const { return log_prefix_; }

private:
  std::string makeLogPrefix() const;

  const std::string key_;
  const std::string log_prefix_;
};

struct BufferBase : public BufferInterface {
  BufferBase() = default;
  ~BufferBase() override = default;

  // BufferInterface
  size_t size() const override { return data_.size(); }
  int64_t copyTo(void* ptr_ptr, uint64_t size_ptr) override;
  WasmResult copyFrom(size_t /* start */, std::string_view /* data */, size_t /* length */
                      ) override {
    // Setting a string buffer not supported (no use case).
    return WasmResult::BadArgument;
  }

  virtual void clear() { data_ = ""; }
  BufferBase* set(std::string_view data) {
    clear();
    data_ = data;
    return this;
  }

protected:
  std::string_view data_;
};

/**
 * ContextBase is the interface between the VM host and the VM. It has several uses:
 *
 * 1) To provide host-specific implementations of ABI calls out of the VM.
 * 2) To call into the VM. For example, when a new HTTP request arrives and the
 * headers are available, the host must create a new ContextBase object to manage the new stream and
 * call onRequestHeaders() on that object which will cause a handle_request ABI to be called in the
 * VM.
 */
class ContextBase : public RootInterface,
                    public HttpInterface,
                    public HeaderInterface,
                    public GeneralInterface {
public:
  ContextBase();                                                          // Testing.
  ContextBase(WasmBase* wasm);                                            // Vm Context.
  ContextBase(WasmBase* wasm, const std::shared_ptr<PluginBase>& plugin); // Root Context.
  ContextBase(WasmBase* wasm, uint32_t parent_context_id,
              const std::shared_ptr<PluginHandleBase>& plugin_handle); // Stream context.
  virtual ~ContextBase();

  WasmBase* wasm() const { return wasm_; }
  // virtual void maybeAddContentLength(uint64_t content_length);
  uint32_t id() const { return id_; }
  // Root Contexts have the VM Context as a parent.
  bool isRootContext() const { return parent_context_id_ == 0; }
  ContextBase* parent_context() const { return parent_context_; }
  ContextBase* root_context() const {
    const ContextBase* previous = this;
    ContextBase* parent = parent_context_;
    while (parent != previous) {
      previous = parent;
      parent = parent->parent_context_;
    }
    return parent;
  }
  std::string_view root_id() const { return isRootContext() ? root_id_ : plugin_->root_id_; }
  std::string_view log_prefix() const {
    return isRootContext() ? root_log_prefix_ : plugin_->log_prefix();
  }
  WasmVm* wasmVm() const;

  // Called before deleting the context.
  virtual void destroy();

  /**
   * Calls into the VM.
   * These are implemented by the proxy-independent host code. They are virtual to support some
   * types of testing.
   */

  // Context
  void onCreate() override;
  bool onDone() override;
  void onLog() override;
  void onDelete() override;

  // Root
  bool onStart(std::shared_ptr<PluginBase> plugin) override;

  // HTTP
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(uint32_t body_length, bool end_of_stream) override;
  FilterTrailersStatus onRequestTrailers(uint32_t trailers) override;
  FilterMetadataStatus onRequestMetadata(uint32_t elements) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(uint32_t body_length, bool end_of_stream) override;
  FilterTrailersStatus onResponseTrailers(uint32_t trailers) override;
  FilterMetadataStatus onResponseMetadata(uint32_t elements) override;
  void sendLocalResponse(uint32_t /* response_code */) override { unimplemented(); }

  void error(std::string_view message) override {
    std::cerr << message << "\n";
    abort();
  }
  WasmResult unimplemented() override {
    error("unimplemented proxy-wasm API");
    return WasmResult::Unimplemented;
  }
  bool isFailed();
  bool isFailOpen() { return plugin_->fail_open_; }

  //
  // General Callbacks.
  //
  WasmResult log(uint32_t /* level */, std::string_view /* message */) override {
    return unimplemented();
  }

  uint32_t getLogLevel() override {
    unimplemented();
    return 0;
  }
  uint64_t getCurrentTimeNanoseconds() override {
    unimplemented();
    return 0;
  }
  uint64_t getMonotonicTimeNanoseconds() override {
    unimplemented();
    return 0;
  }
  std::string_view getConfiguration() override {
    unimplemented();
    return "";
  }
  // Buffer
  BufferInterface* getBuffer(WasmBufferType /* type */) override {
    unimplemented();
    return nullptr;
  }

  // Header/Trailer/Metadata Maps
  virtual void maybeAddContentLength(uint64_t) { unimplemented(); }

  WasmResult addHeaderMapValue(WasmHeaderMapType /* type */, std::string_view /* key */,
                               std::string_view /* value */) override {
    return unimplemented();
  }
  WasmResult getHeaderMapValue(WasmHeaderMapType /* type */, std::string_view /* key */,
                               std::string_view* /*result */) override {
    return unimplemented();
  }

  WasmResult removeHeaderMapValue(WasmHeaderMapType /* type */,
                                  std::string_view /* key */) override {
    return unimplemented();
  }
  WasmResult replaceHeaderMapValue(WasmHeaderMapType /* type */, std::string_view /* key */,
                                   std::string_view /* value */) override {
    return unimplemented();
  }

  WasmResult getHeaderMapSize(WasmHeaderMapType /* type */, uint32_t* /* result */) override {
    return unimplemented();
  }
  // Actions to be done after the call into the VM returns.
  std::deque<std::function<void()>> after_vm_call_actions_;

  void addAfterVmCallAction(std::function<void()> f) { after_vm_call_actions_.push_back(f); }
  void doAfterVmCallActions() {
    if (!after_vm_call_actions_.empty()) {
      while (!after_vm_call_actions_.empty()) {
        auto f = std::move(after_vm_call_actions_.front());
        after_vm_call_actions_.pop_front();
        f();
      }
    }
  }

protected:
  friend class WasmBase;

  std::string makeRootLogPrefix(std::string_view vm_id) const;

  WasmBase* wasm_{nullptr};
  uint32_t id_{0};
  uint32_t parent_context_id_{0};                   // 0 for roots and the general context.
  ContextBase* parent_context_{nullptr};            // set in all contexts.
  std::string root_id_;                             // set only in root context.
  std::string root_log_prefix_;                     // set only in root context.
  std::shared_ptr<PluginBase> plugin_;              // set in root and stream contexts.
  std::shared_ptr<PluginHandleBase> plugin_handle_; // set only in stream context.
  bool in_vm_context_created_ = false;
  bool destroyed_ = false;
  bool stream_failed_ = false; // Set true after failStream is called in case of VM failure.

private:
  // helper functions
  FilterHeadersStatus convertVmCallResultToFilterHeadersStatus(uint64_t result);
  FilterDataStatus convertVmCallResultToFilterDataStatus(uint64_t result);
  FilterTrailersStatus convertVmCallResultToFilterTrailersStatus(uint64_t result);
  FilterMetadataStatus convertVmCallResultToFilterMetadataStatus(uint64_t result);
};

class DeferAfterCallActions {
public:
  DeferAfterCallActions(ContextBase* context) : context_(context) {}
  ~DeferAfterCallActions();

private:
  ContextBase* const context_;
};

} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
