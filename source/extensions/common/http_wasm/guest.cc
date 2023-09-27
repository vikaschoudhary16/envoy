#include "envoy/server/lifecycle_notifier.h"
#include "source/common/config/datasource.h"
#include "source/extensions/common/http_wasm/guest.h"
#include "source/extensions/common/http_wasm/v8/v8.h"
#include "source/extensions/common/http_wasm/exports.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"
//#include "vm.h"
#include <openssl/sha.h>
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

namespace {
// Map from Wasm Key to the local Wasm instance.
thread_local std::unordered_map<std::string, std::weak_ptr<InitializedGuestHandle>>
    local_initialized_guests;
const std::string INLINE_STRING = "<inline>";

inline Guest* getGuest(GuestHandleSharedPtr& guest_handle) { return guest_handle->guest().get(); }

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

void Guest::initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier) {
  auto weak = std::weak_ptr<Guest>(std::static_pointer_cast<Guest>(shared_from_this()));
  lifecycle_notifier.registerCallback(Server::ServerLifecycleNotifier::Stage::ShutdownExit,
                                      [this, weak](Event::PostCb post_cb) {
                                        auto lock = weak.lock();
                                        if (lock) { // See if we are still alive.
                                          server_shutdown_post_cb_ = std::move(post_cb);
                                        }
                                      });
}

Guest::Guest(GuestConfig& config, const Stats::ScopeSharedPtr& scope, Api::Api& api,
             Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher)
    : scope_(scope), api_(api), stat_name_pool_(scope_->symbolTable()),
      cluster_manager_(cluster_manager), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()), runtime_(createV8Client()) {

  if (!runtime_) {
    failed_ = FailState::UnableToCreateVm;
    ENVOY_LOG(error, "Failed to create guest");
    return;
  }
  runtime_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  ENVOY_LOG(debug, "Guest created now active");
}

Guest::Guest(GuestHandleSharedPtr guest_handle, Event::Dispatcher& dispatcher)
    : std::enable_shared_from_this<Guest>(*guest_handle->guest()),
      scope_(getGuest(guest_handle)->scope_), api_(getGuest(guest_handle)->api_),
      stat_name_pool_(scope_->symbolTable()),
      cluster_manager_(getGuest(guest_handle)->clusterManager()), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()) {
  parent_guest_handle_ = guest_handle;
  runtime_ = guest_handle->guest()->runtime()->clone();
  if (!runtime_) {
    failed_ = FailState::UnableToCreateVm;
    return;
  }
  runtime_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  ENVOY_LOG(debug, "Thread-Local Guest created now active");
}

void Guest::error(std::string_view message) { ENVOY_LOG(error, "Guest VM failed {}", message); }

Guest::~Guest() {
  ENVOY_LOG(debug, "~Guest remaining active");
  if (server_shutdown_post_cb_) {
    dispatcher_.post(std::move(server_shutdown_post_cb_));
  }
}

uint32_t Guest::allocContextId() {
  while (true) {
    auto id = next_context_id_++;
    // Prevent reuse.
    if (contexts_.find(id) == contexts_.end()) {
      return id;
    }
  }
}

void Guest::registerCallbacks() {
#define _REGISTER(_fn)                                                                             \
  runtime_->registerCallback(                                                                      \
      "env", #_fn, &exports::_fn,                                                                  \
      &ConvertFunctionWordToUint32<decltype(exports::_fn),                                         \
                                   exports::_fn>::convertFunctionWordToUint32)
#undef _REGISTER

  // Register the capability with the VM if it has been allowed, otherwise register a stub.
#define _REGISTER(module_name, export_prefix, _fn)                                                 \
  if (capabilityAllowed(#_fn)) {                                                                   \
    runtime_->registerCallback(                                                                    \
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

void Guest::getFunctions() {
#define _GET(_fn) runtime_->getFunction(#_fn, &_fn##_);
#define _GET_ALIAS(_fn, _alias) runtime_->getFunction(#_alias, &_fn##_);
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
    runtime_->getFunction(#_fn, &_fn##_);                                                          \
  } else {                                                                                         \
    _fn##_ = nullptr;                                                                              \
  }

  FOR_ALL_MODULE_FUNCTIONS(_GET_PROXY);

#undef _GET_PROXY
}

Context* Guest::createContext(const std::shared_ptr<InitializedGuest>& initialized_guest) {
  return new Context(this, initialized_guest);
}

Context* Guest::createRootContext(const std::shared_ptr<InitializedGuest>& initialized_guest) {
  return new Context(this, initialized_guest);
}

bool Guest::load(const std::string& code) {
  assert(!started_from_.has_value());

  if (!runtime_) {
    return false;
  }

  // Verify signature.
  std::string message;

  if (!message.empty()) {
    runtime_->logger()->debug(message);
  }

  // Get function names from the module.
  if (!BytecodeUtil::getFunctionNameIndex(code, function_names_)) {
    fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Guest module");
    return false;
  }

  // Get original bytecode (possibly stripped).
  std::string stripped;
  if (!BytecodeUtil::getStrippedSource(code, stripped)) {
    fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Guest module");
    return false;
  }

  auto ok = runtime_->load(stripped, "" /*precompiled*/, function_names_);
  if (!ok) {
    fail(FailState::UnableToInitializeCode, "Failed to load Guest bytecode");
    return false;
  }

  return true;
}

bool Guest::initializeAndStart(Context* initialized_guest_context) {
  if (!runtime_) {
    return false;
  }
  // TODO(vikas): I think we can remove this whole Cloneable thing.
  if (started_from_ == Cloneable::NotCloneable) {
    auto ok =
        runtime_->load(parent_guest_handle_->guest()->moduleBytecode(),
                       /*modulePrecompiled*/ "", parent_guest_handle_->guest()->functionNames());
    if (!ok) {
      fail(FailState::UnableToInitializeCode, "Failed to load Guest module from base Guest");
      return false;
    }
  }

  if (started_from_ != Cloneable::InstantiatedModule) {
    registerCallbacks();
    if (!runtime_->link("")) {
      return false;
    }
  }
  getFunctions();
  if (started_from_ != Cloneable::InstantiatedModule) {
    // Base VM was already started, so don't try to start cloned VMs again.
    start(initialized_guest_context);
  }

  return !isFailed();
}

void Guest::start(Context* context) {
  if (_initialize_) {
    // WASI reactor.
    _initialize_(context);
    if (main_) {
      // Call main() if it exists in WASI reactor, to allow module to
      // do early initialization (e.g. configure SDK).
      //
      // Re-using main() keeps this consistent when switching between
      // WASI command (that calls main()) and reactor (that doesn't).
      main_(context, Word(0), Word(0));
    }
  } else if (_start_) {
    // WASI command.
    _start_(context);
  }
}

Context* Guest::getOrCreateInitializedGuestContext(
    const std::shared_ptr<InitializedGuest>& initialized_guest) {
  auto context = std::unique_ptr<Context>(createRootContext(initialized_guest));
  auto* context_ptr = context.get();
  initialized_guest_context_ = std::move(context);
  return context_ptr;
};

static GuestHandleFactory
getGuestHandleFactory(GuestConfig& guest_config, const Stats::ScopeSharedPtr& scope, Api::Api& api,
                      Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
                      Server::ServerLifecycleNotifier& lifecycle_notifier) {
  return [&guest_config, &scope, &api, &cluster_manager, &dispatcher,
          &lifecycle_notifier]() -> GuestHandleSharedPtr {
    auto wasm = std::make_shared<Guest>(guest_config, scope, api, cluster_manager, dispatcher);
    wasm->initializeLifecycle(lifecycle_notifier);
    return std::make_shared<GuestHandle>(std::move(wasm));
  };
}

static GuestHandleCloneFactory getGuestHandleCloneFactory(Event::Dispatcher& dispatcher) {
  return [&dispatcher](GuestHandleSharedPtr wasm) -> std::shared_ptr<GuestHandle> {
    auto clone = std::make_shared<Guest>(wasm, dispatcher);
    return std::make_shared<GuestHandle>(std::move(clone));
  };
}

static InitializedGuestHandleFactory getInitializedGuestHandleFactory() {
  return
      [](GuestHandleSharedPtr wasm,
         InitializedGuestSharedPtr initialized_guest) -> std::shared_ptr<InitializedGuestHandle> {
        return std::make_shared<InitializedGuestHandle>(wasm, initialized_guest);
      };
}

bool loadGuest(const InitializedGuestSharedPtr& initialized_guest,
               const Stats::ScopeSharedPtr& scope, Upstream::ClusterManager& cluster_manager,
               Event::Dispatcher& dispatcher, Api::Api& api,
               Server::ServerLifecycleNotifier& lifecycle_notifier, loadGuestCallback&& cb) {
  std::string code;
  auto config = initialized_guest->wasmConfig();

  if (config.config().code().has_local()) {
    code = Config::DataSource::read(config.config().code().local(), true, api);
  }

  auto complete_cb = [cb, initialized_guest, scope, &api, &cluster_manager, &dispatcher,
                      &lifecycle_notifier](std::string code) -> bool {
    if (code.empty()) {
      cb(nullptr);
      return false;
    }

    auto config = initialized_guest->wasmConfig();
    auto guest_handle = loadGuest(
        code, initialized_guest,
        getGuestHandleFactory(config, scope, api, cluster_manager, dispatcher, lifecycle_notifier));
    if (!guest_handle || guest_handle->guest()->isFailed()) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                          "Unable to create Guest");
      cb(nullptr);
      return false;
    }
    cb(guest_handle);
    return true;
  };
  return complete_cb(code);
}

std::shared_ptr<GuestHandle> loadGuest(const std::string& code,
                                       const std::shared_ptr<InitializedGuest>&,
                                       const GuestHandleFactory& factory) {
  std::shared_ptr<GuestHandle> guest_handle;
  guest_handle = factory();
  if (!guest_handle) {
    return nullptr;
  }
  if (!guest_handle->guest()->load(code)) {
    guest_handle->guest()->fail(FailState::UnableToInitializeCode, "Failed to load Guest code");
    return nullptr;
  }
  return guest_handle;
}

InitializedGuestHandleSharedPtr
getOrCreateThreadLocalInitializedGuest(const GuestHandleSharedPtr& guest_handle_main,
                                       const InitializedGuestSharedPtr& initialized_guest,
                                       Event::Dispatcher& dispatcher) {
  if (!guest_handle_main) {
    if (!initialized_guest->fail_open_) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), critical,
                          "InitializedGuest configured to fail closed failed to load");
    }
    // To handle the case when failed to create VMs and fail-open/close properly,
    // we still create InitializedGuestHandle with null Guest.
    return std::make_shared<InitializedGuestHandle>(nullptr, initialized_guest);
  }

  auto key = initialized_guest->key();
  // Get existing thread-local InitializedGuest handle.
  auto it = local_initialized_guests.find(key);
  if (it != local_initialized_guests.end()) {
    auto initialized_guest_handle = it->second.lock();
    if (initialized_guest_handle) {
      return initialized_guest_handle;
    }
    // Remove stale entry.
    local_initialized_guests.erase(key);
  }
  // Get thread-local WasmVM.
  auto guest_handle = getOrCreateThreadLocalGuestCodeCache(
      guest_handle_main, getGuestHandleCloneFactory(dispatcher), key);
  if (!guest_handle) {
    return nullptr;
  }
  // Create and initialize new thread-local InitializedGuest.
  auto* initialized_guest_context =
      guest_handle->guest()->getOrCreateInitializedGuestContext(initialized_guest);
  if (initialized_guest_context == nullptr) {
    guest_handle_main->guest()->fail(FailState::StartFailed, "Failed to start thread-local Wasm");
    return nullptr;
  }
  if (!guest_handle->guest()->initializeAndStart(initialized_guest_context)) {
    guest_handle_main->guest()->fail(FailState::UnableToInitializeCode,
                                     "Failed to initialize Wasm code");
    return nullptr;
  }
  auto initialized_guest_factory = getInitializedGuestHandleFactory();
  auto initialized_guest_handle = initialized_guest_factory(guest_handle, initialized_guest);
  local_initialized_guests[key] = initialized_guest_handle;
  guest_handle->guest()->runtime()->addFailCallback([key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local initialized_guest from the same
      // guest_code_cache. 2) we wouldn't reuse the failed VM for new initialized_guest configs
      // accidentally.
      local_initialized_guests.erase(key);
    };
  });
  return initialized_guest_handle;
}

static std::shared_ptr<GuestHandle>
getOrCreateThreadLocalGuestCodeCache(const std::shared_ptr<GuestHandle>& handle,
                                     const GuestHandleCloneFactory& clone_factory,
                                     std::string_view vm_key) {
  // Create and initialize new thread-local WasmVM.
  auto guest_handle = clone_factory(handle);
  if (!guest_handle) {
    handle->guest()->fail(FailState::UnableToCloneVm, "Failed to clone Base Wasm");
    return nullptr;
  }

  guest_handle->guest()->runtime()->addFailCallback([vm_key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local VM from the same guest_code_cache.
      // 2) we wouldn't reuse the failed VM for new initialized_guests accidentally.
      local_initialized_guests.erase(std::string(vm_key));
    };
  });
  return guest_handle;
}

uint32_t InitializedGuestHandle::rootContextId() {
  return guest_handle_->guest()->getRootContext()->id();
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
