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
class Guest;
using EnvironmentVariableMap = std::unordered_map<std::string, std::string>;

using WasmVmFactory = std::function<std::unique_ptr<Runtime>()>;
using GuestFactory = std::function<std::shared_ptr<Guest>()>;
using GuestCloneFactory = std::function<std::shared_ptr<Guest>(std::shared_ptr<Guest> guest)>;

class GuestConfig;

// Guest represents a single WebAssembly VM instance.
class Guest : public Logger::Loggable<Logger::Id::wasm>,
              public std::enable_shared_from_this<Guest> {
public:
  // This is used to create clonable main thread local Guest
  Guest(const Stats::ScopeSharedPtr& scope, Api::Api& api, Event::Dispatcher& dispatcher);
  // This is used to create non-clonable thread local Guest, cloned from main thread Guest.
  Guest(std::shared_ptr<Guest> main_thread_guest, Event::Dispatcher& dispatcher);
  ~Guest();

  Event::Dispatcher& dispatcher() { return dispatcher_; }
  std::shared_ptr<Guest> sharedThis() {
    return std::static_pointer_cast<Guest>(shared_from_this());
  }

  void initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier);
  bool load(const std::string& code);

  // This is used to link the exported host functions and start the thread local guest.
  bool initializeAndStart(Context* guest_context);
  void start(Context* guest_context);

  // Returns the guest_config Context.
  Context* createGuestContext(const std::shared_ptr<GuestConfig>& guest_config);

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

  // Proxy specific extension points.
  //
  void registerCallbacks(); // Register functions called out from guest.
  void getFunctions();      // Get functions call into guest.

  virtual Context* createContext(std::shared_ptr<GuestConfig>& guest_config);
  template <typename T> bool setDatatype(uint64_t ptr, const T& t);
  void fail(FailState fail_state, std::string_view message) {
    error(message);
    failed_ = fail_state;
  }
  void error(std::string_view message);
  const std::unordered_map<std::string, std::string>& envs() { return envs_; }

protected:
  friend class Context;

  Stats::ScopeSharedPtr scope_;
  Api::Api& api_;
  Event::Dispatcher& dispatcher_;
  Event::PostCb server_shutdown_post_cb_;
  TimeSource& time_source_;

  std::unique_ptr<Runtime> runtime_;

  uint32_t next_context_id_ = 0;
  std::unique_ptr<Context> guest_config_context_; // Guest context
  std::unordered_map<std::string, std::unique_ptr<Context>> pending_done_;
  std::unordered_set<std::unique_ptr<Context>> pending_delete_;
  std::unordered_map<uint32_t, Context*> contexts_; // Contains all contexts.
  std::unordered_map<std::string, std::string>
      envs_; // environment variables passed through wasi.environ_get

  WasmCallVoid<0> _initialize_; /* WASI reactor (Emscripten v1.39.17+, Rust nightly) */
  WasmCallVoid<0> _start_;      /* WASI command (Emscripten v1.39.0+, TinyGo) */

  WasmCallWord<2> main_;

  // Calls into the VM.
  WasmCallI64<0> handle_request_;   // http-wasm
  WasmCallVoid<2> handle_response_; // http-wasm

  std::shared_ptr<Guest> parent_guest_;

  // Used by the unguest_config to enable non-clonable thread local Guest(s) to be constructed.
  std::string module_bytecode_;
  std::string module_precompiled_;
  std::unordered_map<uint32_t, std::string> function_names_;

  std::string vm_configuration_;
  bool stop_iteration_ = false;
  FailState failed_ = FailState::Ok; // Guest fatal error
};
using GuestSharedPtr = std::shared_ptr<Guest>;

// InitializedGuestAndGuestConfig is a pair of a guest(running wasm instance) and its guest_config.
// An instance of this class is used as a value of a thread local slot.
class InitializedGuestAndGuestConfig
    : public std::enable_shared_from_this<InitializedGuestAndGuestConfig> {
public:
  explicit InitializedGuestAndGuestConfig(std::shared_ptr<Guest> guest,
                                          std::shared_ptr<GuestConfig> guest_config)
      : guest_config_(guest_config), guest_(guest) {}
  std::shared_ptr<GuestConfig>& guestConfig() { return guest_config_; }
  std::shared_ptr<Guest>& guest() { return guest_; }

private:
  std::shared_ptr<GuestConfig> guest_config_;
  std::shared_ptr<Guest> guest_;
};

using GuestAndGuestConfigSharedPtr = std::shared_ptr<InitializedGuestAndGuestConfig>;
class GuestAndGuestConfigSharedPtrThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  GuestAndGuestConfigSharedPtrThreadLocal(GuestAndGuestConfigSharedPtr mapping)
      : mapping_(mapping){};
  GuestAndGuestConfigSharedPtr& mapping() { return mapping_; }

private:
  GuestAndGuestConfigSharedPtr mapping_;
};

using loadGuestCallbackToRegisterTlsSlot = std::function<void(GuestSharedPtr)>;

// This is used to read the module binary and load the module into runtime from main thread,
// which is used later to create the cloneable thread local guest instances.
bool loadGuestAndSetTlsSlot(const GuestConfigSharedPtr& guest_config,
                            const Stats::ScopeSharedPtr& scope, Event::Dispatcher& dispatcher,
                            Api::Api& api,
                            Envoy::Server::ServerLifecycleNotifier& lifecycle_notifier,
                            loadGuestCallbackToRegisterTlsSlot&& callback);

static std::shared_ptr<Guest> cloneGuest(const std::shared_ptr<Guest>& handle,
                                         const GuestCloneFactory& clone_factory,
                                         std::string_view vm_key);

GuestAndGuestConfigSharedPtr
getOrCreateThreadLocalInitializedGuest(const GuestSharedPtr& guest,
                                       const GuestConfigSharedPtr& guest_config,
                                       Event::Dispatcher& dispatcher);

template <typename T> inline bool Guest::setDatatype(uint64_t ptr, const T& t) {
  return runtime_->setMemory(ptr, sizeof(T), &t);
}
void removeStaleLocalCacheEntries();

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
