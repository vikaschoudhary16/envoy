#pragma once

#include "contrib/http_wasm/filters/http/source/plugin.h"
#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/vm_runtime.h"
#include "contrib/http_wasm/filters/http/source/bytecode_util.h"
#include "envoy/server/lifecycle_notifier.h"
//#include "source/common/config/datasource.h"
//#include "source/extensions/common/wasm/stats_handler.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
class WasmHandle;
using EnvironmentVariableMap = std::unordered_map<std::string, std::string>;

// using Common::Wasm::WasmEvent;
//  using Host::FailState;
//   using Host::Runtime;
using WasmVmFactory = std::function<std::unique_ptr<Runtime>()>;
using WasmHandleFactory = std::function<std::shared_ptr<WasmHandle>(std::string_view vm_id)>;
using WasmHandleCloneFactory =
    std::function<std::shared_ptr<WasmHandle>(std::shared_ptr<WasmHandle> wasm)>;
using CallOnThreadFunction = std::function<void(std::function<void()>)>;

class WasmConfig;
class Wasm : public Logger::Loggable<Logger::Id::wasm>, public std::enable_shared_from_this<Wasm> {
public:
  Wasm(WasmConfig& config, absl::string_view vm_key, const Stats::ScopeSharedPtr& scope,
       Api::Api& api, Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher);
  Wasm(std::shared_ptr<WasmHandle> other, Event::Dispatcher& dispatcher);
  ~Wasm();

  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  Event::Dispatcher& dispatcher() { return dispatcher_; }
  // Api::Api& api() { return api_; }
  Context* getRootContext() { return plugin_context_.get(); }
  std::shared_ptr<Wasm> sharedThis() { return std::static_pointer_cast<Wasm>(shared_from_this()); }

  // // AccessLog::Instance
  // void log(const PluginSharedPtr& plugin, const Http::RequestHeaderMap* request_headers,
  //          const Http::ResponseHeaderMap* response_headers,
  //          const Http::ResponseTrailerMap* response_trailers,
  //          const StreamInfo::StreamInfo& stream_info, AccessLog::AccessLogType access_log_type);

  void initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier);
  bool load(const std::string& code, bool allow_precompiled = false);
  bool initializeAndStart(Context* plugin_context);
  void startVm(Context* plugin_context);
  bool configure(Context* plugin_context, std::shared_ptr<Plugin> plugin);
  // Returns the plugin Context.
  Context* getOrCreatePluginContext(const std::shared_ptr<Plugin>& plugin);

  std::string_view vm_id() const { return vm_id_; }
  std::string_view vm_key() const { return vm_key_; }
  Runtime* wasm_vm() const { return runtime_.get(); }
  Context* getContext(uint32_t id) {
    auto it = contexts_.find(id);
    if (it != contexts_.end())
      return it->second;
    return nullptr;
  }
  uint32_t allocContextId();
  bool isFailed() { return failed_ != FailState::Ok; }
  FailState fail_state() { return failed_; }

  const std::string& vm_configuration() const;

  const std::string& moduleBytecode() const { return module_bytecode_; }
  const std::string& modulePrecompiled() const { return module_precompiled_; }
  const std::unordered_map<uint32_t, std::string> functionNames() const { return function_names_; }

  void timerReady(uint32_t plugin_context_id);
  void queueReady(uint32_t plugin_context_id, uint32_t token);

  WasmResult done(Context* plugin_context);

  // Proxy specific extension points.
  //
  void registerCallbacks(); // Register functions called out from Wasm.
  void getFunctions();      // Get functions call into Wasm.
  virtual CallOnThreadFunction callOnThreadFunction() {
    unimplemented();
    return nullptr;
  }

  // Capability restriction (restricting/exposing the ABI).
  bool capabilityAllowed(std::string capability_name) {
    return allowed_capabilities_.empty() ||
           allowed_capabilities_.find(capability_name) != allowed_capabilities_.end();
  }

  Context* createRootContext(const std::shared_ptr<Plugin>& plugin);
  virtual Context* createContext(const std::shared_ptr<Plugin>& plugin);
  template <typename T> bool setDatatype(uint64_t ptr, const T& t);
  void fail(FailState fail_state, std::string_view message) {
    error(message);
    failed_ = fail_state;
  }
  void error(std::string_view message);
  virtual void unimplemented() { error("unimplemented http-wasm API"); }

  const std::unordered_map<std::string, std::string>& envs() { return envs_; }

protected:
  friend class Context;

  Stats::ScopeSharedPtr scope_;
  Api::Api& api_;
  Stats::StatNamePool stat_name_pool_;
  // const Stats::StatName custom_stat_namespace_;
  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;
  Event::PostCb server_shutdown_post_cb_;
  absl::flat_hash_map<uint32_t, Event::TimerPtr> timer_; // per root_id.
  TimeSource& time_source_;

  // // Lifecycle stats
  // Common::Wasm::LifecycleStatsHandler lifecycle_stats_handler_;

  std::string vm_id_;  // User-provided vm_id.
  std::string vm_key_; // vm_id + hash of code.
  std::unique_ptr<Runtime> runtime_;
  std::optional<Cloneable> started_from_;

  uint32_t next_context_id_ = 1;            // 0 is reserved for the VM context.
  std::unique_ptr<Context> plugin_context_; // Plugin Context
  std::unordered_map<std::string, std::unique_ptr<Context>> pending_done_; // Root contexts.
  std::unordered_set<std::unique_ptr<Context>> pending_delete_;            // Root contexts.
  std::unordered_map<uint32_t, Context*> contexts_;                        // Contains all contexts.
  std::unordered_map<uint32_t, std::chrono::milliseconds> timer_period_;   // per root_id.
  std::unordered_map<std::string, std::string>
      envs_; // environment variables passed through wasi.environ_get

  WasmCallVoid<0> _initialize_; /* WASI reactor (Emscripten v1.39.17+, Rust nightly) */
  WasmCallVoid<0> _start_;      /* WASI command (Emscripten v1.39.0+, TinyGo) */

  WasmCallWord<2> main_;

  // Calls into the VM.
  WasmCallI64<0> handle_request_; // http-wasm

#define FOR_ALL_MODULE_FUNCTIONS(_f) _f(handle_request)

  // Capabilities which are allowed to be linked to the module. If this is empty, restriction
  // is not enforced.
  AllowedCapabilitiesMap allowed_capabilities_;

  std::shared_ptr<WasmHandle> parent_wasm_handle_;

  // Used by the base_wasm to enable non-clonable thread local Wasm(s) to be constructed.
  std::string module_bytecode_;
  std::string module_precompiled_;
  std::unordered_map<uint32_t, std::string> function_names_;

  std::string vm_configuration_;
  bool stop_iteration_ = false;
  FailState failed_ = FailState::Ok; // Wasm VM fatal error
};
using WasmSharedPtr = std::shared_ptr<Wasm>;

class WasmHandle : public ThreadLocal::ThreadLocalObject,
                   public std::enable_shared_from_this<WasmHandle> {
public:
  explicit WasmHandle(std::shared_ptr<Wasm> wasm_) : wasm_(wasm_) {}

  bool canary(const std::shared_ptr<Plugin>& plugin, const WasmHandleCloneFactory& clone_factory);

  void kill() { wasm_ = nullptr; }

  std::shared_ptr<Wasm>& wasm() { return wasm_; }

protected:
  std::shared_ptr<Wasm> wasm_;
  std::unordered_map<std::string, bool> plugin_canary_cache_;
};
using WasmHandleSharedPtr = std::shared_ptr<WasmHandle>;

std::string makeVmKey(std::string_view vm_id, std::string_view configuration,
                      std::string_view code);

class PluginHandle : public std::enable_shared_from_this<PluginHandle> {
public:
  explicit PluginHandle(std::shared_ptr<WasmHandle> wasm_handle, std::shared_ptr<Plugin> plugin)
      : plugin_(plugin), wasm_handle_(wasm_handle) {}
  std::shared_ptr<Plugin>& plugin() { return plugin_; }
  std::shared_ptr<Wasm>& wasm() { return wasm_handle_->wasm(); }
  WasmHandleSharedPtr& wasmHandle() { return wasm_handle_; }
  uint32_t rootContextId();

private:
  std::shared_ptr<Plugin> plugin_;
  std::shared_ptr<WasmHandle> wasm_handle_;
};

using PluginHandleSharedPtr = std::shared_ptr<PluginHandle>;
class PluginHandleSharedPtrThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  PluginHandleSharedPtrThreadLocal(PluginHandleSharedPtr handle) : handle_(handle){};
  PluginHandleSharedPtr& handle() { return handle_; }

private:
  PluginHandleSharedPtr handle_;
};

using createVmCallback = std::function<void(WasmHandleSharedPtr)>;
bool createVm(const PluginSharedPtr& plugin, const Stats::ScopeSharedPtr& scope,
              Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
              Api::Api& api, Envoy::Server::ServerLifecycleNotifier& lifecycle_notifier,
              createVmCallback&& callback);
// Returns nullptr on failure (i.e. initialization of the VM fails).
std::shared_ptr<WasmHandle> createVm(const std::string& vm_key, const std::string& code,
                                     const std::shared_ptr<Plugin>& plugin,
                                     const WasmHandleFactory& factory, bool allow_precompiled);

using PluginHandleFactory = std::function<std::shared_ptr<PluginHandle>(
    std::shared_ptr<WasmHandle> wasm, std::shared_ptr<Plugin> plugin)>;

static std::shared_ptr<WasmHandle>
getOrCreateThreadLocalWasm(const std::shared_ptr<WasmHandle>& handle,
                           const WasmHandleCloneFactory& clone_factory, std::string_view vm_key);

PluginHandleSharedPtr getOrCreateThreadLocalPlugin(const WasmHandleSharedPtr& base_wasm,
                                                   const PluginSharedPtr& plugin,
                                                   Event::Dispatcher& dispatcher);

std::shared_ptr<PluginHandle> getOrCreateThreadLocalPlugin(
    const std::shared_ptr<WasmHandle>& handle, const std::shared_ptr<Plugin>& plugin,
    const WasmHandleCloneFactory& clone_factory, const PluginHandleFactory& plugin_factory);

template <typename T> inline bool Wasm::setDatatype(uint64_t ptr, const T& t) {
  return runtime_->setMemory(ptr, sizeof(T), &t);
}

// WasmEvent toWasmEvent(const std::shared_ptr<WasmHandleBase>& wasm);

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
