#include <mutex>
#include <cassert>

#include "contrib/http_wasm/filters/http/source/host/vm.h"
#include <openssl/sha.h>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace Host {

namespace {

// Map from Wasm Key to the local Wasm instance.
thread_local std::unordered_map<std::string, std::weak_ptr<PluginHandleBase>> local_plugins;
std::mutex base_wasms_mutex;
std::unordered_map<std::string, std::weak_ptr<WasmHandleBase>>* base_wasms = nullptr;

std::vector<uint8_t> Sha256(const std::vector<std::string_view>& parts) {
  uint8_t sha256[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  for (auto part : parts) {
    SHA256_Update(&sha_ctx, part.data(), part.size());
  }
  SHA256_Final(sha256, &sha_ctx);
  return std::vector<uint8_t>(std::begin(sha256), std::end(sha256));
}

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
  static const char* const hex = "0123456789ABCDEF";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (auto byte : bytes) {
    result.push_back(hex[byte >> 4]);
    result.push_back(hex[byte & 0xf]);
  }
  return result;
}

} // namespace

std::string makeVmKey(std::string_view vm_id, std::string_view vm_configuration,
                      std::string_view code) {
  return BytesToHex(Sha256({vm_id, vm_configuration, code}));
}

void WasmBase::registerCallbacks() {
#define _REGISTER(_fn)                                                                             \
  wasm_vm_->registerCallback(                                                                      \
      "env", #_fn, &exports::_fn,                                                                  \
      &ConvertFunctionWordToUint32<decltype(exports::_fn),                                         \
                                   exports::_fn>::convertFunctionWordToUint32)
#undef _REGISTER

  // Register the capability with the VM if it has been allowed, otherwise register a stub.
#define _REGISTER(module_name, export_prefix, _fn)                                                 \
  if (capabilityAllowed(#_fn)) {                                                                   \
    wasm_vm_->registerCallback(                                                                    \
        module_name, #_fn, &exports::export_prefix##_fn,                                           \
        &ConvertFunctionWordToUint32<decltype(exports::export_prefix##_fn),                        \
                                     exports::export_prefix##_fn>::convertFunctionWordToUint32);   \
  }

#define _REGISTER_WASI_UNSTABLE(_fn) _REGISTER("wasi_unstable", wasi_unstable_, _fn)
#define _REGISTER_WASI_SNAPSHOT(_fn) _REGISTER("wasi_snapshot_preview1", wasi_unstable_, _fn)
  FOR_ALL_WASI_FUNCTIONS(_REGISTER_WASI_UNSTABLE);
  FOR_ALL_WASI_FUNCTIONS(_REGISTER_WASI_SNAPSHOT);
#undef _REGISTER_WASI_UNSTABLE
#undef _REGISTER_WASI_SNAPSHOT

#define _REGISTER_HTTP_HANDLER(_fn) _REGISTER("http_handler", , _fn)
  FOR_ALL_HOST_FUNCTIONS(_REGISTER_HTTP_HANDLER);

#undef _REGISTER_HTTP_HANDLER

#undef _REGISTER
}

void WasmBase::getFunctions() {
#define _GET(_fn) wasm_vm_->getFunction(#_fn, &_fn##_);
#define _GET_ALIAS(_fn, _alias) wasm_vm_->getFunction(#_alias, &_fn##_);
  _GET(_initialize);
  if (_initialize_) {
    _GET(main);
  } else {
    _GET(_start);
  }
#undef _GET_ALIAS
#undef _GET

  // Try to point the capability to one of the module exports, if the capability has been allowed.
#define _GET_PROXY(_fn)                                                                            \
  if (capabilityAllowed(#_fn)) {                                                                   \
    wasm_vm_->getFunction(#_fn, &_fn##_);                                                          \
  } else {                                                                                         \
    _fn##_ = nullptr;                                                                              \
  }

  FOR_ALL_MODULE_FUNCTIONS(_GET_PROXY);

#undef _GET_PROXY
}

WasmBase::WasmBase(const std::shared_ptr<WasmHandleBase>& base_wasm_handle,
                   const WasmVmFactory& factory)
    : std::enable_shared_from_this<WasmBase>(*base_wasm_handle->wasm()),
      vm_id_(base_wasm_handle->wasm()->vm_id_), vm_key_(base_wasm_handle->wasm()->vm_key_),
      started_from_(base_wasm_handle->wasm()->wasm_vm()->cloneable()),
      envs_(base_wasm_handle->wasm()->envs()),
      allowed_capabilities_(base_wasm_handle->wasm()->allowed_capabilities_),
      base_wasm_handle_(base_wasm_handle) {
  if (started_from_ != Cloneable::NotCloneable) {
    wasm_vm_ = base_wasm_handle->wasm()->wasm_vm()->clone();
  } else {
    wasm_vm_ = factory();
  }
  if (!wasm_vm_) {
    failed_ = FailState::UnableToCreateVm;
  } else {
    wasm_vm_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  }
}

WasmBase::WasmBase(std::unique_ptr<WasmVm> wasm_vm, std::string_view vm_id,
                   std::string_view vm_configuration, std::string_view vm_key,
                   std::unordered_map<std::string, std::string> envs,
                   AllowedCapabilitiesMap allowed_capabilities)
    : vm_id_(std::string(vm_id)), vm_key_(std::string(vm_key)), wasm_vm_(std::move(wasm_vm)),
      envs_(std::move(envs)), allowed_capabilities_(std::move(allowed_capabilities)),
      vm_configuration_(std::string(vm_configuration)) {
  if (!wasm_vm_) {
    failed_ = FailState::UnableToCreateVm;
  } else {
    wasm_vm_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  }
}

WasmBase::~WasmBase() {
  pending_done_.clear();
  pending_delete_.clear();
}

bool WasmBase::load(const std::string& code, bool allow_precompiled) {
  assert(!started_from_.has_value());

  if (!wasm_vm_) {
    return false;
  }

  // Verify signature.
  std::string message;

  if (!message.empty()) {
    wasm_vm_->integration()->debug(message);
  }

  // Get function names from the module.
  if (!BytecodeUtil::getFunctionNameIndex(code, function_names_)) {
    fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Wasm module");
    return false;
  }

  std::string_view precompiled = {};

  if (allow_precompiled) {
    // Check if precompiled module exists.
    const auto section_name = wasm_vm_->getPrecompiledSectionName();
    if (!section_name.empty()) {
      if (!BytecodeUtil::getCustomSection(code, section_name, precompiled)) {
        fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Wasm module");
        return false;
      }
    }
  }

  // Get original bytecode (possibly stripped).
  std::string stripped;
  if (!BytecodeUtil::getStrippedSource(code, stripped)) {
    fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Wasm module");
    return false;
  }

  auto ok = wasm_vm_->load(stripped, precompiled, function_names_);
  if (!ok) {
    fail(FailState::UnableToInitializeCode, "Failed to load Wasm bytecode");
    return false;
  }

  // Store for future use in non-cloneable Wasm engines.
  if (wasm_vm_->cloneable() == Cloneable::NotCloneable) {
    module_bytecode_ = stripped;
    module_precompiled_ = precompiled;
  }

  return true;
}

bool WasmBase::initialize(ContextBase* plugin_context) {
  if (!wasm_vm_) {
    return false;
  }

  if (started_from_ == Cloneable::NotCloneable) {
    auto ok = wasm_vm_->load(base_wasm_handle_->wasm()->moduleBytecode(),
                             base_wasm_handle_->wasm()->modulePrecompiled(),
                             base_wasm_handle_->wasm()->functionNames());
    if (!ok) {
      fail(FailState::UnableToInitializeCode, "Failed to load Wasm module from base Wasm");
      return false;
    }
  }

  if (started_from_ != Cloneable::InstantiatedModule) {
    registerCallbacks();
    if (!wasm_vm_->link(vm_id_)) {
      return false;
    }
  }
  getFunctions();
  if (started_from_ != Cloneable::InstantiatedModule) {
    // Base VM was already started, so don't try to start cloned VMs again.
    startVm(plugin_context);
  }

  return !isFailed();
}

ContextBase* WasmBase::getRootContext() { return plugin_context_.get(); }

void WasmBase::startVm(ContextBase* root_context) {
  if (_initialize_) {
    // WASI reactor.
    _initialize_(root_context);
    if (main_) {
      // Call main() if it exists in WASI reactor, to allow module to
      // do early initialization (e.g. configure SDK).
      //
      // Re-using main() keeps this consistent when switching between
      // WASI command (that calls main()) and reactor (that doesn't).
      main_(root_context, Word(0), Word(0));
    }
  } else if (_start_) {
    // WASI command.
    _start_(root_context);
  }
}

ContextBase* WasmBase::start(const std::shared_ptr<PluginBase>& plugin) {
  auto context = std::unique_ptr<ContextBase>(createRootContext(plugin));
  auto* context_ptr = context.get();
  plugin_context_ = std::move(context);
  if (!context_ptr->onStart(plugin)) {
    return nullptr;
  }
  return context_ptr;
};

uint32_t WasmBase::allocContextId() {
  while (true) {
    auto id = next_context_id_++;
    // Prevent reuse.
    if (contexts_.find(id) == contexts_.end()) {
      return id;
    }
  }
}

std::shared_ptr<WasmHandleBase> createWasm(const std::string& vm_key, const std::string& code,
                                           const std::shared_ptr<PluginBase>&,
                                           const WasmHandleFactory& factory,
                                           bool allow_precompiled) {
  std::shared_ptr<WasmHandleBase> wasm_handle;
  {
    std::lock_guard<std::mutex> guard(base_wasms_mutex);
    if (base_wasms == nullptr) {
      base_wasms = new std::remove_reference<decltype(*base_wasms)>::type;
    }
    auto it = base_wasms->find(vm_key);
    if (it != base_wasms->end()) {
      wasm_handle = it->second.lock();
      if (!wasm_handle) {
        base_wasms->erase(it);
      }
    }
    if (!wasm_handle) {
      // If no cached base_wasm, creates a new base_wasm, loads the code and initializes it.
      wasm_handle = factory(vm_key);
      if (!wasm_handle) {
        return nullptr;
      }
      if (!wasm_handle->wasm()->load(code, allow_precompiled)) {
        wasm_handle->wasm()->fail(FailState::UnableToInitializeCode, "Failed to load Wasm code");
        return nullptr;
      }
      (*base_wasms)[vm_key] = wasm_handle;
    }
  }
  return wasm_handle;
}

static std::shared_ptr<WasmHandleBase>
getOrCreateThreadLocalWasm(const std::shared_ptr<WasmHandleBase>& base_handle,
                           const WasmHandleCloneFactory& clone_factory, std::string_view vm_key) {
  // Create and initialize new thread-local WasmVM.
  auto wasm_handle = clone_factory(base_handle);
  if (!wasm_handle) {
    base_handle->wasm()->fail(FailState::UnableToCloneVm, "Failed to clone Base Wasm");
    return nullptr;
  }

  wasm_handle->wasm()->wasm_vm()->addFailCallback([vm_key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local VM from the same base_wasm.
      // 2) we wouldn't reuse the failed VM for new plugins accidentally.
      local_plugins.erase(std::string(vm_key));
    };
  });
  return wasm_handle;
}

std::shared_ptr<PluginHandleBase> getOrCreateThreadLocalPlugin(
    const std::shared_ptr<WasmHandleBase>& base_handle, const std::shared_ptr<PluginBase>& plugin,
    const WasmHandleCloneFactory& clone_factory, const PluginHandleFactory& plugin_factory) {
  std::string key(std::string(base_handle->wasm()->vm_key()) + "||" + plugin->key());
  // Get existing thread-local Plugin handle.
  auto it = local_plugins.find(key);
  if (it != local_plugins.end()) {
    auto plugin_handle = it->second.lock();
    if (plugin_handle) {
      return plugin_handle;
    }
    // Remove stale entry.
    local_plugins.erase(key);
  }
  // Get thread-local WasmVM.
  auto wasm_handle = getOrCreateThreadLocalWasm(base_handle, clone_factory, key);
  if (!wasm_handle) {
    return nullptr;
  }
  // Create and initialize new thread-local Plugin.
  auto* plugin_context = wasm_handle->wasm()->start(plugin);
  if (plugin_context == nullptr) {
    base_handle->wasm()->fail(FailState::StartFailed, "Failed to start thread-local Wasm");
    return nullptr;
  }
  if (!wasm_handle->wasm()->initialize(plugin_context)) {
    base_handle->wasm()->fail(FailState::UnableToInitializeCode, "Failed to initialize Wasm code");
    return nullptr;
  }
  auto plugin_handle = plugin_factory(wasm_handle, plugin);
  local_plugins[key] = plugin_handle;
  wasm_handle->wasm()->wasm_vm()->addFailCallback([key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local plugin from the same base_wasm.
      // 2) we wouldn't reuse the failed VM for new plugin configs accidentally.
      local_plugins.erase(key);
    };
  });
  return plugin_handle;
}

} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
