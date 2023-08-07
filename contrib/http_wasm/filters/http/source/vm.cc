#include "envoy/server/lifecycle_notifier.h"
#include "source/common/config/datasource.h"
#include "contrib/http_wasm/filters/http/source/vm.h"
#include "contrib/http_wasm/filters/http/source/v8/v8.h"
#include "contrib/http_wasm/filters/http/source/exports.h"
#include "contrib/http_wasm/filters/http/source/vm.h"
//#include "source/extensions/common/wasm/stats_handler.h"
#include "contrib/http_wasm/filters/http/source/vm_runtime.h"
#include "vm.h"
#include <openssl/sha.h>
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

namespace {
// Map from Wasm Key to the local Wasm instance.
thread_local std::unordered_map<std::string, std::weak_ptr<PluginHandle>> local_plugins;
std::mutex wasms_mutex;
std::unordered_map<std::string, std::weak_ptr<WasmHandle>>* wasms = nullptr;

const std::string INLINE_STRING = "<inline>";

inline Wasm* getWasm(WasmHandleSharedPtr& wasm_handle) { return wasm_handle->wasm().get(); }

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

void Wasm::initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier) {
  auto weak = std::weak_ptr<Wasm>(std::static_pointer_cast<Wasm>(shared_from_this()));
  lifecycle_notifier.registerCallback(Server::ServerLifecycleNotifier::Stage::ShutdownExit,
                                      [this, weak](Event::PostCb post_cb) {
                                        auto lock = weak.lock();
                                        if (lock) { // See if we are still alive.
                                          server_shutdown_post_cb_ = std::move(post_cb);
                                        }
                                      });
}

Wasm::Wasm(WasmConfig& config, absl::string_view vm_key, const Stats::ScopeSharedPtr& scope,
           Api::Api& api, Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher)
    // : WasmBase(
    //       createWasmVm(config.config().vm_config().runtime()),
    //       config.config().vm_config().vm_id(),
    //       MessageUtil::anyToBytes(config.config().vm_config().configuration()),
    //       toStdStringView(vm_key), config.environmentVariables(), config.allowedCapabilities()),
    : scope_(scope), api_(api), stat_name_pool_(scope_->symbolTable()),
      // custom_stat_namespace_(stat_name_pool_.add(Common::Wasm::CustomStatNamespace)),
      cluster_manager_(cluster_manager), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()),
      // lifecycle_stats_handler_(
      //     Common::Wasm::LifecycleStatsHandler(scope, config.config().vm_config().runtime())),
      // runtime_(std::move(createWasmVm(config.config().vm_config().runtime()))) {
      runtime_(createV8Client()) {

  if (!runtime_) {
    failed_ = FailState::UnableToCreateVm;
    ENVOY_LOG(error, "Failed to create VM");
    return;
  }
  runtime_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  // lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmCreated);
  ENVOY_LOG(debug, "Wasm VM created now active");
}

Wasm::Wasm(WasmHandleSharedPtr wasm_handle, Event::Dispatcher& dispatcher)
    : // : Wasm(wasm_handle,
      //        [&wasm_handle]() {
      //          return createWasmVm(
      //              absl::StrCat("envoy.wasm.runtime.",
      //                           toAbslStringView(wasm_handle->wasm()->wasm_vm()->getEngineName())));
      //        }),
      std::enable_shared_from_this<Wasm>(*wasm_handle->wasm()),
      scope_(getWasm(wasm_handle)->scope_), api_(getWasm(wasm_handle)->api_),
      stat_name_pool_(scope_->symbolTable()),
      // custom_stat_namespace_(stat_name_pool_.add(Common::Wasm::CustomStatNamespace)),
      cluster_manager_(getWasm(wasm_handle)->clusterManager()), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()) {
  // lifecycle_stats_handler_(getWasm(wasm_handle)->lifecycle_stats_handler_) {
  parent_wasm_handle_ = wasm_handle;
  runtime_ = wasm_handle->wasm()->wasm_vm()->clone();
  if (!runtime_) {
    failed_ = FailState::UnableToCreateVm;
    return;
  }
  runtime_->addFailCallback([this](FailState fail_state) { failed_ = fail_state; });
  // lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmCreated);
  ENVOY_LOG(debug, "Thread-Local Wasm vm created now active");
  // lifecycle_stats_handler_.getActiveVmCount());
}

void Wasm::error(std::string_view message) { ENVOY_LOG(error, "Wasm VM failed {}", message); }

Wasm::~Wasm() {
  // lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmShutDown);
  // ENVOY_LOG(debug, "~Wasm {} remaining active", lifecycle_stats_handler_.getActiveVmCount());
  ENVOY_LOG(debug, "~Wasm remaining active");
  if (server_shutdown_post_cb_) {
    dispatcher_.post(std::move(server_shutdown_post_cb_));
  }
}

uint32_t Wasm::allocContextId() {
  while (true) {
    auto id = next_context_id_++;
    // Prevent reuse.
    if (contexts_.find(id) == contexts_.end()) {
      return id;
    }
  }
}

void Wasm::registerCallbacks() {
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

void Wasm::getFunctions() {
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

Context* Wasm::createContext(const std::shared_ptr<Plugin>& plugin) {
  return new Context(this, plugin);
}

Context* Wasm::createRootContext(const std::shared_ptr<Plugin>& plugin) {
  return new Context(this, plugin);
}

bool Wasm::load(const std::string& code, bool allow_precompiled) {
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
    fail(FailState::UnableToInitializeCode, "Failed to parse corrupted Wasm module");
    return false;
  }

  std::string_view precompiled = {};

  if (allow_precompiled) {
    // Check if precompiled module exists.
    const auto section_name = runtime_->getPrecompiledSectionName();
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

  auto ok = runtime_->load(stripped, precompiled, function_names_);
  if (!ok) {
    fail(FailState::UnableToInitializeCode, "Failed to load Wasm bytecode");
    return false;
  }

  return true;
}

bool Wasm::initializeAndStart(Context* plugin_context) {
  if (!runtime_) {
    return false;
  }
  // TODO(vikas): I think we can remove this whole Cloneable thing.
  if (started_from_ == Cloneable::NotCloneable) {
    auto ok = runtime_->load(parent_wasm_handle_->wasm()->moduleBytecode(),
                             parent_wasm_handle_->wasm()->modulePrecompiled(),
                             parent_wasm_handle_->wasm()->functionNames());
    if (!ok) {
      fail(FailState::UnableToInitializeCode, "Failed to load Wasm module from base Wasm");
      return false;
    }
  }

  if (started_from_ != Cloneable::InstantiatedModule) {
    registerCallbacks();
    if (!runtime_->link(vm_id_)) {
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

void Wasm::startVm(Context* root_context) {
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

Context* Wasm::getOrCreatePluginContext(const std::shared_ptr<Plugin>& plugin) {
  auto context = std::unique_ptr<Context>(createRootContext(plugin));
  auto* context_ptr = context.get();
  plugin_context_ = std::move(context);
  return context_ptr;
};

// void Wasm::log(const PluginSharedPtr&, const Http::RequestHeaderMap* request_headers,
//                const Http::ResponseHeaderMap* response_headers,
//                const Http::ResponseTrailerMap* response_trailers,
//                const StreamInfo::StreamInfo& stream_info,
//                AccessLog::AccessLogType access_log_type) {
//   auto context = getRootContext();
//   context->log(request_headers, response_headers, response_trailers, stream_info,
//   access_log_type);
// }

static WasmHandleFactory getWasmHandleFactory(WasmConfig& wasm_config,
                                              const Stats::ScopeSharedPtr& scope, Api::Api& api,
                                              Upstream::ClusterManager& cluster_manager,
                                              Event::Dispatcher& dispatcher,
                                              Server::ServerLifecycleNotifier& lifecycle_notifier) {
  return [&wasm_config, &scope, &api, &cluster_manager, &dispatcher,
          &lifecycle_notifier](std::string_view vm_key) -> WasmHandleSharedPtr {
    auto wasm = std::make_shared<Wasm>(wasm_config, toAbslStringView(vm_key), scope, api,
                                       cluster_manager, dispatcher);
    wasm->initializeLifecycle(lifecycle_notifier);
    return std::make_shared<WasmHandle>(std::move(wasm));
  };
}

static WasmHandleCloneFactory getWasmHandleCloneFactory(Event::Dispatcher& dispatcher) {
  return [&dispatcher](WasmHandleSharedPtr wasm) -> std::shared_ptr<WasmHandle> {
    auto clone = std::make_shared<Wasm>(wasm, dispatcher);
    return std::make_shared<WasmHandle>(std::move(clone));
  };
}

static PluginHandleFactory getPluginHandleFactory() {
  return [](WasmHandleSharedPtr wasm, PluginSharedPtr plugin) -> std::shared_ptr<PluginHandle> {
    return std::make_shared<PluginHandle>(wasm, plugin);
  };
}

bool createVm(const PluginSharedPtr& plugin, const Stats::ScopeSharedPtr& scope,
              Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
              Api::Api& api, Server::ServerLifecycleNotifier& lifecycle_notifier,
              createVmCallback&& cb) {
  // auto& stats_handler = Common::Wasm::getCreateStatsHandler();
  std::string source, code;
  auto config = plugin->wasmConfig();
  auto vm_config = config.config().vm_config();

  if (vm_config.code().has_local()) {
    code = Config::DataSource::read(vm_config.code().local(), true, api);
    source = Config::DataSource::getPath(vm_config.code().local())
                 .value_or(code.empty() ? EMPTY_STRING : INLINE_STRING);
  }

  auto vm_key =
      makeVmKey(vm_config.vm_id(), MessageUtil::anyToBytes(vm_config.configuration()), code);
  auto complete_cb = [cb, vm_key, plugin, scope, &api, &cluster_manager, &dispatcher,
                      &lifecycle_notifier](std::string code) -> bool {
    if (code.empty()) {
      cb(nullptr);
      return false;
    }

    auto config = plugin->wasmConfig();
    auto wasm = createVm(
        vm_key, code, plugin,
        getWasmHandleFactory(config, scope, api, cluster_manager, dispatcher, lifecycle_notifier),
        config.config().vm_config().allow_precompiled());
    if (!wasm || wasm->wasm()->isFailed()) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                          "Unable to create Wasm");
      cb(nullptr);
      return false;
    }
    cb(wasm);
    return true;
  };
  return complete_cb(code);
}

std::shared_ptr<WasmHandle> createVm(const std::string& vm_key, const std::string& code,
                                     const std::shared_ptr<Plugin>&,
                                     const WasmHandleFactory& factory, bool allow_precompiled) {
  std::shared_ptr<WasmHandle> wasm_handle;
  {
    std::lock_guard<std::mutex> guard(wasms_mutex);
    if (wasms == nullptr) {
      wasms = new std::remove_reference<decltype(*wasms)>::type;
    }
    auto it = wasms->find(vm_key);
    if (it != wasms->end()) {
      wasm_handle = it->second.lock();
      if (!wasm_handle) {
        wasms->erase(it);
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
      (*wasms)[vm_key] = wasm_handle;
    }
  }
  return wasm_handle;
}

PluginHandleSharedPtr getOrCreateThreadLocalPlugin(const WasmHandleSharedPtr& wasm_handle_main,
                                                   const PluginSharedPtr& plugin,
                                                   Event::Dispatcher& dispatcher) {
  if (!wasm_handle_main) {
    if (!plugin->fail_open_) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), critical,
                          "Plugin configured to fail closed failed to load");
    }
    // To handle the case when failed to create VMs and fail-open/close properly,
    // we still create PluginHandle with null Wasm.
    return std::make_shared<PluginHandle>(nullptr, plugin);
  }

  std::string key(std::string(wasm_handle_main->wasm()->vm_key()) + "||" + plugin->key());
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
  auto wasm_handle =
      getOrCreateThreadLocalWasm(wasm_handle_main, getWasmHandleCloneFactory(dispatcher), key);
  if (!wasm_handle) {
    return nullptr;
  }
  // Create and initialize new thread-local Plugin.
  auto* plugin_context = wasm_handle->wasm()->getOrCreatePluginContext(plugin);
  if (plugin_context == nullptr) {
    wasm_handle_main->wasm()->fail(FailState::StartFailed, "Failed to start thread-local Wasm");
    return nullptr;
  }
  if (!wasm_handle->wasm()->initializeAndStart(plugin_context)) {
    wasm_handle_main->wasm()->fail(FailState::UnableToInitializeCode,
                                   "Failed to initialize Wasm code");
    return nullptr;
  }
  auto plugin_factory = getPluginHandleFactory();
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

static std::shared_ptr<WasmHandle>
getOrCreateThreadLocalWasm(const std::shared_ptr<WasmHandle>& handle,
                           const WasmHandleCloneFactory& clone_factory, std::string_view vm_key) {
  // Create and initialize new thread-local WasmVM.
  auto wasm_handle = clone_factory(handle);
  if (!wasm_handle) {
    handle->wasm()->fail(FailState::UnableToCloneVm, "Failed to clone Base Wasm");
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

uint32_t PluginHandle::rootContextId() { return wasm_handle_->wasm()->getRootContext()->id(); }

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
