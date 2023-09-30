#pragma once

#include "source/extensions/common/http_wasm/guest_config.h"
#include "source/extensions/common/http_wasm/context.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"
#include "source/extensions/common/http_wasm/bytecode_util.h"
#include "envoy/server/lifecycle_notifier.h"
#include <memory>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
class GuestHandle;
using EnvironmentVariableMap = std::unordered_map<std::string, std::string>;

using WasmVmFactory = std::function<std::unique_ptr<Runtime>()>;
using GuestHandleFactory = std::function<std::shared_ptr<GuestHandle>()>;
using GuestHandleCloneFactory =
    std::function<std::shared_ptr<GuestHandle>(std::shared_ptr<GuestHandle> wasm)>;
using CallOnThreadFunction = std::function<void(std::function<void()>)>;

class GuestConfig;
class Guest : public Logger::Loggable<Logger::Id::wasm>,
              public std::enable_shared_from_this<Guest> {
public:
  Guest(GuestConfig& config, const Stats::ScopeSharedPtr& scope, Api::Api& api,
        Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher);
  Guest(std::shared_ptr<GuestHandle> other, Event::Dispatcher& dispatcher);
  ~Guest();

  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  Event::Dispatcher& dispatcher() { return dispatcher_; }
  Context* getRootContext() { return initialized_guest_context_.get(); }
  std::shared_ptr<Guest> sharedThis() {
    return std::static_pointer_cast<Guest>(shared_from_this());
  }

  void initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier);
  bool load(const std::string& code);
  bool initializeAndStart(Context* initialized_guest_context);
  void start(Context* initialized_guest_context);

  // Returns the initialized_guest Context.
  Context*
  getOrCreateInitializedGuestContext(const std::shared_ptr<InitializedGuest>& initialized_guest);

  Runtime* runtime() const { return runtime_.get(); }
  Context* getContext(uint32_t id) {
    auto it = contexts_.find(id);
    if (it != contexts_.end())
      return it->second;
    return nullptr;
  }
  uint32_t allocContextId();
  bool isFailed() { return failed_ != FailState::Ok; }
  FailState fail_state() { return failed_; }

  const std::string& moduleBytecode() const { return module_bytecode_; }
  const std::unordered_map<uint32_t, std::string> functionNames() const { return function_names_; }

  void timerReady(uint32_t initialized_guest_context_id);
  void queueReady(uint32_t initialized_guest_context_id, uint32_t token);

  WasmResult done(Context* initialized_guest_context);

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

  virtual Context* createContext(std::shared_ptr<InitializedGuest>& initialized_guest);
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

  std::unique_ptr<Runtime> runtime_;
  std::optional<Cloneable> started_from_;

  uint32_t next_context_id_ = 1;                       // 0 is reserved for the VM context.
  std::unique_ptr<Context> initialized_guest_context_; // InitializedGuest Context
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
  WasmCallI64<0> handle_request_;   // http-wasm
  WasmCallVoid<2> handle_response_; // http-wasm

#define FOR_ALL_MODULE_FUNCTIONS(_f) _f(handle_request) _f(handle_response)

  // Capabilities which are allowed to be linked to the module. If this is empty, restriction
  // is not enforced.
  AllowedCapabilitiesMap allowed_capabilities_;

  std::shared_ptr<GuestHandle> parent_guest_handle_;

  // Used by the uninitialized_guest to enable non-clonable thread local Guest(s) to be constructed.
  std::string module_bytecode_;
  std::string module_precompiled_;
  std::unordered_map<uint32_t, std::string> function_names_;

  std::string vm_configuration_;
  bool stop_iteration_ = false;
  FailState failed_ = FailState::Ok; // Guest fatal error
};
using GuestSharedPtr = std::shared_ptr<Guest>;

class GuestHandle : public ThreadLocal::ThreadLocalObject,
                    public std::enable_shared_from_this<GuestHandle> {
public:
  explicit GuestHandle(std::shared_ptr<Guest> guest_) : guest_(guest_) {}

  bool canary(const std::shared_ptr<InitializedGuest>& initialized_guest,
              const GuestHandleCloneFactory& clone_factory);

  void kill() { guest_ = nullptr; }

  std::shared_ptr<Guest>& guest() { return guest_; }

protected:
  std::shared_ptr<Guest> guest_;
  std::unordered_map<std::string, bool> initialized_guest_canary_cache_;
};
using GuestHandleSharedPtr = std::shared_ptr<GuestHandle>;

std::string makeVmKey(std::string_view vm_id, std::string_view configuration,
                      std::string_view code);

class InitializedGuestHandle : public std::enable_shared_from_this<InitializedGuestHandle> {
public:
  explicit InitializedGuestHandle(std::shared_ptr<GuestHandle> guest_handle,
                                  std::shared_ptr<InitializedGuest> initialized_guest)
      : initialized_guest_(initialized_guest), guest_handle_(guest_handle) {}
  std::shared_ptr<InitializedGuest>& initializedGuest() { return initialized_guest_; }
  std::shared_ptr<Guest>& guest() { return guest_handle_->guest(); }
  GuestHandleSharedPtr& wasmHandle() { return guest_handle_; }
  uint32_t rootContextId();

private:
  std::shared_ptr<InitializedGuest> initialized_guest_;
  std::shared_ptr<GuestHandle> guest_handle_;
};

using InitializedGuestHandleSharedPtr = std::shared_ptr<InitializedGuestHandle>;
class InitializedGuestHandleSharedPtrThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  InitializedGuestHandleSharedPtrThreadLocal(InitializedGuestHandleSharedPtr handle)
      : handle_(handle){};
  InitializedGuestHandleSharedPtr& handle() { return handle_; }

private:
  InitializedGuestHandleSharedPtr handle_;
};

using loadGuestCallback = std::function<void(GuestHandleSharedPtr)>;
bool loadGuest(const InitializedGuestSharedPtr& initialized_guest,
               const Stats::ScopeSharedPtr& scope, Upstream::ClusterManager& cluster_manager,
               Event::Dispatcher& dispatcher, Api::Api& api,
               Envoy::Server::ServerLifecycleNotifier& lifecycle_notifier,
               loadGuestCallback&& callback);
// Returns nullptr on failure (i.e. initialization of the VM fails).
std::shared_ptr<GuestHandle> loadGuest(const std::string& code,
                                       const std::shared_ptr<InitializedGuest>& initialized_guest,
                                       const GuestHandleFactory& factory);

using InitializedGuestHandleFactory = std::function<std::shared_ptr<InitializedGuestHandle>(
    std::shared_ptr<GuestHandle> wasm, std::shared_ptr<InitializedGuest> initialized_guest)>;

static std::shared_ptr<GuestHandle>
getOrCreateThreadLocalGuestCodeCache(const std::shared_ptr<GuestHandle>& handle,
                                     const GuestHandleCloneFactory& clone_factory,
                                     std::string_view vm_key);

InitializedGuestHandleSharedPtr
getOrCreateThreadLocalInitializedGuest(const GuestHandleSharedPtr& uninitialized_guest,
                                       const InitializedGuestSharedPtr& initialized_guest,
                                       Event::Dispatcher& dispatcher);

std::shared_ptr<InitializedGuestHandle> getOrCreateThreadLocalInitializedGuest(
    const std::shared_ptr<GuestHandle>& handle,
    const std::shared_ptr<InitializedGuest>& initialized_guest,
    const GuestHandleCloneFactory& clone_factory,
    const InitializedGuestHandleFactory& initialized_guest_factory);

template <typename T> inline bool Guest::setDatatype(uint64_t ptr, const T& t) {
  return runtime_->setMemory(ptr, sizeof(T), &t);
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
