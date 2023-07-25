#pragma once
#include <memory>
#include <string.h>

#include "contrib/http_wasm/filters/http/source/host/vm_runtime.h"
#include "contrib/http_wasm/filters/http/source/host/bytecode_util.h"
#include "contrib/http_wasm/filters/http/source/host/vm.h"
#include "contrib/http_wasm/filters/http/source/host/exports.h"
#include "contrib/http_wasm/filters/http/source/host/context.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace Host {

class ContextBase;
class WasmHandleBase;

using WasmVmFactory = std::function<std::unique_ptr<WasmVm>()>;
using WasmHandleFactory = std::function<std::shared_ptr<WasmHandleBase>(std::string_view vm_id)>;
using WasmHandleCloneFactory =
    std::function<std::shared_ptr<WasmHandleBase>(std::shared_ptr<WasmHandleBase> wasm)>;
using CallOnThreadFunction = std::function<void(std::function<void()>)>;
struct SanitizationConfig {
  std::vector<std::string> argument_list;
  bool is_allowlist;
};
using AllowedCapabilitiesMap = std::unordered_map<std::string, SanitizationConfig>;
using WasmHandleBaseSharedPtr = std::shared_ptr<WasmHandleBase>;
class WasmBase : public std::enable_shared_from_this<WasmBase> {
public:
  WasmBase(std::unique_ptr<WasmVm> wasm_vm, std::string_view vm_id,
           std::string_view vm_configuration, std::string_view vm_key,
           std::unordered_map<std::string, std::string> envs,
           AllowedCapabilitiesMap allowed_capabilities);
  WasmBase(const std::shared_ptr<WasmHandleBase>& base_wasm_handle, const WasmVmFactory& factory);
  virtual ~WasmBase();

  bool load(const std::string& code, bool allow_precompiled = false);
  bool initialize(ContextBase* plugin_context);
  void startVm(ContextBase* plugin_context);
  bool configure(ContextBase* plugin_context, std::shared_ptr<PluginBase> plugin);
  // Returns the root ContextBase or nullptr if onStart returns false.
  ContextBase* start(const std::shared_ptr<PluginBase>& plugin);

  std::string_view vm_id() const { return vm_id_; }
  std::string_view vm_key() const { return vm_key_; }
  WasmVm* wasm_vm() const { return wasm_vm_.get(); }
  ContextBase* getRootContext();
  ContextBase* getContext(uint32_t id) {
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

  WasmResult done(ContextBase* plugin_context);

  // Proxy specific extension points.
  //
  virtual void registerCallbacks(); // Register functions called out from Wasm.
  virtual void getFunctions();      // Get functions call into Wasm.
  virtual CallOnThreadFunction callOnThreadFunction() {
    unimplemented();
    return nullptr;
  }

  // Capability restriction (restricting/exposing the ABI).
  bool capabilityAllowed(std::string capability_name) {
    return allowed_capabilities_.empty() ||
           allowed_capabilities_.find(capability_name) != allowed_capabilities_.end();
  }

  virtual ContextBase* createRootContext(const std::shared_ptr<PluginBase>& plugin) {
    return new ContextBase(this, plugin);
  }
  virtual ContextBase* createContext(const std::shared_ptr<PluginBase>& plugin) {
    return new ContextBase(this, plugin);
  }
  template <typename T> bool setDatatype(uint64_t ptr, const T& t);
  void fail(FailState fail_state, std::string_view message) {
    error(message);
    failed_ = fail_state;
  }
  virtual void error(std::string_view message) { std::cerr << message << "\n"; }
  virtual void unimplemented() { error("unimplemented http-wasm API"); }

  const std::unordered_map<std::string, std::string>& envs() { return envs_; }

protected:
  friend class ContextBase;

  void establishEnvironment(); // Language specific environments.

  std::string vm_id_;  // User-provided vm_id.
  std::string vm_key_; // vm_id + hash of code.
  std::unique_ptr<WasmVm> wasm_vm_;
  std::optional<Cloneable> started_from_;

  uint32_t next_context_id_ = 1;                // 0 is reserved for the VM context.
  std::unique_ptr<ContextBase> plugin_context_; // Plugin Context
  std::unordered_map<std::string, std::unique_ptr<ContextBase>> pending_done_; // Root contexts.
  std::unordered_set<std::unique_ptr<ContextBase>> pending_delete_;            // Root contexts.
  std::unordered_map<uint32_t, ContextBase*> contexts_;                  // Contains all contexts.
  std::unordered_map<uint32_t, std::chrono::milliseconds> timer_period_; // per root_id.
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

  std::shared_ptr<WasmHandleBase> base_wasm_handle_;

  // Used by the base_wasm to enable non-clonable thread local Wasm(s) to be constructed.
  std::string module_bytecode_;
  std::string module_precompiled_;
  std::unordered_map<uint32_t, std::string> function_names_;

  std::string vm_configuration_;
  bool stop_iteration_ = false;
  FailState failed_ = FailState::Ok; // Wasm VM fatal error.
};

// Handle which enables shutdown operations to run post deletion (e.g. post listener drain).
class WasmHandleBase : public std::enable_shared_from_this<WasmHandleBase> {
public:
  explicit WasmHandleBase(std::shared_ptr<WasmBase> wasm_base) : wasm_base_(wasm_base) {}

  bool canary(const std::shared_ptr<PluginBase>& plugin,
              const WasmHandleCloneFactory& clone_factory);

  void kill() { wasm_base_ = nullptr; }

  std::shared_ptr<WasmBase>& wasm() { return wasm_base_; }

protected:
  std::shared_ptr<WasmBase> wasm_base_;
  std::unordered_map<std::string, bool> plugin_canary_cache_;
};

std::string makeVmKey(std::string_view vm_id, std::string_view configuration,
                      std::string_view code);
// Get an existing ThreadLocal VM matching 'vm_key' or nullptr if there isn't one.
// std::shared_ptr<WasmHandleBase> getThreadLocalWasm(std::string_view vm_key);

class PluginHandleBase : public std::enable_shared_from_this<PluginHandleBase> {
public:
  explicit PluginHandleBase(std::shared_ptr<WasmHandleBase> wasm_handle,
                            std::shared_ptr<PluginBase> plugin)
      : plugin_(plugin), wasm_handle_(wasm_handle) {}
  std::shared_ptr<PluginBase>& plugin() { return plugin_; }
  std::shared_ptr<WasmBase>& wasm() { return wasm_handle_->wasm(); }

protected:
  std::shared_ptr<PluginBase> plugin_;
  std::shared_ptr<WasmHandleBase> wasm_handle_;
};

// Returns nullptr on failure (i.e. initialization of the VM fails).
std::shared_ptr<WasmHandleBase> createWasm(const std::string& vm_key, const std::string& code,
                                           const std::shared_ptr<PluginBase>& plugin,
                                           const WasmHandleFactory& factory,
                                           bool allow_precompiled);

using PluginHandleFactory = std::function<std::shared_ptr<PluginHandleBase>(
    std::shared_ptr<WasmHandleBase> base_wasm, std::shared_ptr<PluginBase> plugin)>;

// Get an existing ThreadLocal VM matching 'vm_id' or create one using 'base_wavm' by cloning or by
// using it it as a template.
std::shared_ptr<PluginHandleBase> getOrCreateThreadLocalPlugin(
    const std::shared_ptr<WasmHandleBase>& base_handle, const std::shared_ptr<PluginBase>& plugin,
    const WasmHandleCloneFactory& clone_factory, const PluginHandleFactory& plugin_factory);

inline const std::string& WasmBase::vm_configuration() const {
  if (base_wasm_handle_)
    return base_wasm_handle_->wasm()->vm_configuration_;
  return vm_configuration_;
}
template <typename T> inline bool WasmBase::setDatatype(uint64_t ptr, const T& t) {
  return wasm_vm_->setMemory(ptr, sizeof(T), &t);
}

} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
