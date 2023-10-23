#include "envoy/server/lifecycle_notifier.h"
#include "guest_config.h"
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
// Map from guest config key to mapping of running guest and guest config.
thread_local std::unordered_map<std::string, std::weak_ptr<InitializedGuestAndGuestConfig>>
    local_guest_configs;
const std::string INLINE_STRING = "<inline>";

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

Guest::Guest(const Stats::ScopeSharedPtr& scope, Api::Api& api, Event::Dispatcher& dispatcher)
    : scope_(scope), api_(api), dispatcher_(dispatcher), time_source_(dispatcher.timeSource()),
      runtime_(createV8Runtime()) {

  if (!runtime_) {
    failed_ = FailState::UnableToCreateVm;
    ENVOY_LOG(error, "Failed to create guest");
    return;
  }
  runtime_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  ENVOY_LOG(debug, "Guest created now active");
}

Guest::Guest(GuestSharedPtr guest, Event::Dispatcher& dispatcher)
    : std::enable_shared_from_this<Guest>(*guest), scope_(guest->scope_), api_(guest->api_),
      dispatcher_(dispatcher), time_source_(dispatcher.timeSource()) {
  parent_guest_ = guest;
  runtime_ = guest->runtime()->clone();
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
  runtime_->registerCallback(                                                                      \
      module_name, #_fn, &exports::export_prefix##_fn,                                             \
      &ConvertFunctionWordToUint32<decltype(exports::export_prefix##_fn),                          \
                                   exports::export_prefix##_fn>::convertFunctionWordToUint32);

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
  runtime_->getFunction("_initialize", &_initialize_);
  if (_initialize_) {
    runtime_->getFunction("main", &main_);
  } else {
    runtime_->getFunction("_start", &_start_);
  }
  runtime_->getFunction("handle_request", &handle_request_);
  runtime_->getFunction("handle_response", &handle_response_);
}

Context* Guest::createContext(std::shared_ptr<GuestConfig>& guest_config) {
  return new Context(this->sharedThis(), guest_config);
}

bool Guest::load(const std::string& code) {
  if (!runtime_) {
    return false;
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

bool Guest::initializeAndStart(Context* guest_config_context) {
  if (!runtime_) {
    return false;
  }

  registerCallbacks();
  if (!runtime_->link("")) {
    return false;
  }
  getFunctions();
  start(guest_config_context);

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

Context* Guest::createGuestContext(const std::shared_ptr<GuestConfig>& guest_config) {
  std::shared_ptr<GuestConfig> guestConfig = guest_config;
  auto context = std::unique_ptr<Context>(createContext(guestConfig));
  auto* context_ptr = context.get();
  guest_config_context_ = std::move(context);
  return context_ptr;
};

GuestSharedPtr newGuest(const Stats::ScopeSharedPtr& scope, Api::Api& api,
                        Event::Dispatcher& dispatcher,
                        Server::ServerLifecycleNotifier& lifecycle_notifier) {
  auto guest = std::make_shared<Guest>(scope, api, dispatcher);
  guest->initializeLifecycle(lifecycle_notifier);
  return std::move(guest);
}

static GuestCloneFactory getGuestCloneFactory(Event::Dispatcher& dispatcher) {
  return [&dispatcher](GuestSharedPtr guest) -> std::shared_ptr<Guest> {
    auto clone = std::make_shared<Guest>(guest, dispatcher);
    return clone;
  };
}

bool loadGuestAndSetTlsSlot(const GuestConfigSharedPtr& guest_config,
                            const Stats::ScopeSharedPtr& scope, Event::Dispatcher& dispatcher,
                            Api::Api& api, Server::ServerLifecycleNotifier& lifecycle_notifier,
                            loadGuestCallbackToRegisterTlsSlot&& register_tls_slot_callback) {
  std::string code;
  auto config = guest_config;

  if (guest_config->config().code().has_local()) {
    code = Config::DataSource::read(guest_config->config().code().local(), true, api);
  }

  if (code.empty()) {
    register_tls_slot_callback(nullptr);
    return false;
  }

  std::shared_ptr<Guest> guest;
  guest = newGuest(scope, api, dispatcher, lifecycle_notifier);
  if (!guest) {
    ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), error,
                        "Unable to create Guest");
    register_tls_slot_callback(nullptr);
    return false;
  }
  if (!guest->load(code)) {
    guest->fail(FailState::UnableToInitializeCode, "Failed to load Guest code");
    ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                        "Unable to load Guest");
    register_tls_slot_callback(nullptr);
    return false;
  }

  register_tls_slot_callback(guest);
  return true;
}

GuestAndGuestConfigSharedPtr
getOrCreateThreadLocalInitializedGuest(const GuestSharedPtr& guest,
                                       const GuestConfigSharedPtr& guest_config,
                                       Event::Dispatcher& dispatcher) {
  if (!guest) {
    if (!guest_config->fail_open_) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), critical,
                          "module {} configured to fail closed failed to load");
    }
    // To handle the case when failed to create VMs and fail-open/close properly,
    // we still create InitializedGuestHandle with null Guest.
    return std::make_shared<InitializedGuestAndGuestConfig>(nullptr, guest_config);
  }

  auto key = guest_config->key();
  // Get existing thread-local mapping if it exists.
  auto it = local_guest_configs.find(key);
  if (it != local_guest_configs.end()) {
    auto guest_config_handle = it->second.lock();
    if (guest_config_handle) {
      return guest_config_handle;
    }
    // Remove stale entry.
    local_guest_configs.erase(key);
  }
  // Get thread-local WasmVM.
  auto thread_local_guest = cloneGuest(guest, getGuestCloneFactory(dispatcher), key);
  if (!thread_local_guest) {
    return nullptr;
  }
  // Create and initialize new thread-local Guest.
  auto* guest_context = thread_local_guest->createGuestContext(guest_config);
  if (guest_context == nullptr) {
    guest->fail(FailState::StartFailed, "Failed to create thread-local guest context");
    return nullptr;
  }
  if (!thread_local_guest->initializeAndStart(guest_context)) {
    guest->fail(FailState::UnableToInitializeCode, "Failed to start guest");
    return nullptr;
  }
  auto mapping = std::make_shared<InitializedGuestAndGuestConfig>(thread_local_guest, guest_config);
  local_guest_configs[key] = mapping;
  thread_local_guest->runtime()->addFailCallback([key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local guest_config from the same
      // guest_code_cache. 2) we wouldn't reuse the failed VM for new guest_config configs
      // accidentally.
      local_guest_configs.erase(key);
    };
  });
  removeStaleLocalCacheEntries();
  return mapping;
}

static std::shared_ptr<Guest> cloneGuest(const std::shared_ptr<Guest>& guest,
                                         const GuestCloneFactory& clone_factory,
                                         std::string_view vm_key) {
  // Create and initialize new thread-local WasmVM.
  auto guest_clone = clone_factory(guest);
  if (!guest_clone) {
    guest->fail(FailState::UnableToCloneVm, "Failed to clone Base Wasm");
    return nullptr;
  }

  guest_clone->runtime()->addFailCallback([vm_key](FailState fail_state) {
    if (fail_state == FailState::RuntimeError) {
      // If VM failed, erase the entry so that:
      // 1) we can recreate the new thread local VM from the same guest_code_cache.
      // 2) we wouldn't reuse the failed VM for new guest_configs accidentally.
      local_guest_configs.erase(std::string(vm_key));
    };
  });
  return guest_clone;
}

void removeStaleLocalCacheEntries() {
  // iterate over the cache and remove any expired entries
  for (auto it = local_guest_configs.begin(); it != local_guest_configs.end();) {
    if (it->second.expired()) {
      it = local_guest_configs.erase(it);
    } else {
      ++it;
    }
  }
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
