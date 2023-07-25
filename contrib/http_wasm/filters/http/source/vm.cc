#include "envoy/server/lifecycle_notifier.h"
#include "source/common/config/datasource.h"
#include "contrib/http_wasm/filters/http/source/host/vm.h"
#include "contrib/http_wasm/filters/http/source/host/exports.h"
#include "contrib/http_wasm/filters/http/source/vm.h"
#include "source/extensions/common/wasm/stats_handler.h"
#include "contrib/http_wasm/filters/http/source/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

namespace {

const std::string INLINE_STRING = "<inline>";

// Downcast WasmBase to the actual Wasm.
inline Wasm* getWasm(WasmHandleSharedPtr& base_wasm_handle) {
  return static_cast<Wasm*>(base_wasm_handle->wasm().get());
}

} // namespace

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
    : WasmBase(
          createWasmVm(config.config().vm_config().runtime()), config.config().vm_config().vm_id(),
          MessageUtil::anyToBytes(config.config().vm_config().configuration()),
          toStdStringView(vm_key), config.environmentVariables(), config.allowedCapabilities()),
      scope_(scope), api_(api), stat_name_pool_(scope_->symbolTable()),
      custom_stat_namespace_(stat_name_pool_.add(Common::Wasm::CustomStatNamespace)),
      cluster_manager_(cluster_manager), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()),
      lifecycle_stats_handler_(
          Common::Wasm::LifecycleStatsHandler(scope, config.config().vm_config().runtime())) {
  lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmCreated);
  ENVOY_LOG(debug, "Base Wasm created {} now active", lifecycle_stats_handler_.getActiveVmCount());
}

Wasm::Wasm(WasmHandleSharedPtr base_wasm_handle, Event::Dispatcher& dispatcher)
    : WasmBase(base_wasm_handle,
               [&base_wasm_handle]() {
                 return createWasmVm(absl::StrCat(
                     "envoy.wasm.runtime.",
                     toAbslStringView(base_wasm_handle->wasm()->wasm_vm()->getEngineName())));
               }),
      scope_(getWasm(base_wasm_handle)->scope_), api_(getWasm(base_wasm_handle)->api_),
      stat_name_pool_(scope_->symbolTable()),
      custom_stat_namespace_(stat_name_pool_.add(Common::Wasm::CustomStatNamespace)),
      cluster_manager_(getWasm(base_wasm_handle)->clusterManager()), dispatcher_(dispatcher),
      time_source_(dispatcher.timeSource()),
      lifecycle_stats_handler_(getWasm(base_wasm_handle)->lifecycle_stats_handler_) {
  lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmCreated);
  ENVOY_LOG(debug, "Thread-Local Wasm created {} now active",
            lifecycle_stats_handler_.getActiveVmCount());
}

void Wasm::error(std::string_view message) { ENVOY_LOG(error, "Wasm VM failed {}", message); }

Wasm::~Wasm() {
  lifecycle_stats_handler_.onEvent(Common::Wasm::WasmEvent::VmShutDown);
  ENVOY_LOG(debug, "~Wasm {} remaining active", lifecycle_stats_handler_.getActiveVmCount());
  if (server_shutdown_post_cb_) {
    dispatcher_.post(std::move(server_shutdown_post_cb_));
  }
}

void Wasm::registerCallbacks() { WasmBase::registerCallbacks(); }

void Wasm::getFunctions() { WasmBase::getFunctions(); }

ContextBase* Wasm::createContext(const std::shared_ptr<PluginBase>& plugin) {
  return new Context(this, std::static_pointer_cast<Plugin>(plugin));
}

ContextBase* Wasm::createRootContext(const std::shared_ptr<PluginBase>& plugin) {
  return new Context(this, std::static_pointer_cast<Plugin>(plugin));
}

void Wasm::log(const PluginSharedPtr&, const Http::RequestHeaderMap* request_headers,
               const Http::ResponseHeaderMap* response_headers,
               const Http::ResponseTrailerMap* response_trailers,
               const StreamInfo::StreamInfo& stream_info,
               AccessLog::AccessLogType access_log_type) {
  auto context = getRootContext();
  context->log(request_headers, response_headers, response_trailers, stream_info, access_log_type);
}

static Host::WasmHandleFactory
getWasmHandleFactory(WasmConfig& wasm_config, const Stats::ScopeSharedPtr& scope, Api::Api& api,
                     Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher,
                     Server::ServerLifecycleNotifier& lifecycle_notifier) {
  return [&wasm_config, &scope, &api, &cluster_manager, &dispatcher,
          &lifecycle_notifier](std::string_view vm_key) -> Host::WasmHandleBaseSharedPtr {
    auto wasm = std::make_shared<Wasm>(wasm_config, toAbslStringView(vm_key), scope, api,
                                       cluster_manager, dispatcher);
    wasm->initializeLifecycle(lifecycle_notifier);
    return std::static_pointer_cast<Host::WasmHandleBase>(
        std::make_shared<WasmHandle>(std::move(wasm)));
  };
}

static Host::WasmHandleCloneFactory getWasmHandleCloneFactory(Event::Dispatcher& dispatcher) {
  return [&dispatcher](WasmHandleBaseSharedPtr base_wasm) -> std::shared_ptr<WasmHandleBase> {
    auto wasm = std::make_shared<Wasm>(std::static_pointer_cast<WasmHandle>(base_wasm), dispatcher);
    return std::static_pointer_cast<WasmHandleBase>(std::make_shared<WasmHandle>(std::move(wasm)));
  };
}

static Host::PluginHandleFactory getPluginHandleFactory() {
  return [](WasmHandleBaseSharedPtr base_wasm,
            PluginBaseSharedPtr base_plugin) -> std::shared_ptr<PluginHandleBase> {
    return std::static_pointer_cast<PluginHandleBase>(
        std::make_shared<PluginHandle>(std::static_pointer_cast<WasmHandle>(base_wasm),
                                       std::static_pointer_cast<Plugin>(base_plugin)));
  };
}

WasmEvent toWasmEvent(const std::shared_ptr<WasmHandleBase>& wasm) {
  if (!wasm) {
    return WasmEvent::UnableToCreateVm;
  }
  switch (wasm->wasm()->fail_state()) {
  case FailState::Ok:
    return WasmEvent::Ok;
  case FailState::UnableToCreateVm:
    return WasmEvent::UnableToCreateVm;
  case FailState::UnableToCloneVm:
    return WasmEvent::UnableToCloneVm;
  case FailState::MissingFunction:
    return WasmEvent::MissingFunction;
  case FailState::UnableToInitializeCode:
    return WasmEvent::UnableToInitializeCode;
  case FailState::StartFailed:
    return WasmEvent::StartFailed;
  case FailState::ConfigureFailed:
    return WasmEvent::ConfigureFailed;
  case FailState::RuntimeError:
    return WasmEvent::RuntimeError;
  }
  PANIC("corrupt enum");
}

bool createWasm(const PluginSharedPtr& plugin, const Stats::ScopeSharedPtr& scope,
                Upstream::ClusterManager& cluster_manager, Init::Manager& init_manager,
                Event::Dispatcher& dispatcher, Api::Api& api,
                Server::ServerLifecycleNotifier& lifecycle_notifier,
                Config::DataSource::RemoteAsyncDataProviderPtr& remote_data_provider,
                CreateWasmCallback&& cb) {
  auto& stats_handler = Common::Wasm::getCreateStatsHandler();
  std::string source, code;
  auto config = plugin->wasmConfig();
  auto vm_config = config.config().vm_config();

  if (vm_config.code().has_local()) {
    code = Config::DataSource::read(vm_config.code().local(), true, api);
    source = Config::DataSource::getPath(vm_config.code().local())
                 .value_or(code.empty() ? EMPTY_STRING : INLINE_STRING);
  }

  auto vm_key =
      Host::makeVmKey(vm_config.vm_id(), MessageUtil::anyToBytes(vm_config.configuration()), code);
  auto complete_cb = [cb, vm_key, plugin, scope, &api, &cluster_manager, &dispatcher,
                      &lifecycle_notifier, &stats_handler](std::string code) -> bool {
    //  auto complete_cb = [cb, vm_key, plugin, scope, &stats_handler](std::string code) -> bool {
    if (code.empty()) {
      cb(nullptr);
      return false;
    }

    auto config = plugin->wasmConfig();
    auto wasm = Host::createWasm(
        vm_key, code, plugin,
        getWasmHandleFactory(config, scope, api, cluster_manager, dispatcher, lifecycle_notifier),
        config.config().vm_config().allow_precompiled());
    Stats::ScopeSharedPtr create_wasm_stats_scope = stats_handler.lockAndCreateStats(scope);
    stats_handler.onEvent(toWasmEvent(wasm));
    if (!wasm || wasm->wasm()->isFailed()) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), trace,
                          "Unable to create Wasm");
      cb(nullptr);
      return false;
    }
    cb(std::static_pointer_cast<WasmHandle>(wasm));
    return true;
  };
  return complete_cb(code);
}

PluginHandleSharedPtr getOrCreateThreadLocalPlugin(const WasmHandleSharedPtr& base_wasm,
                                                   const PluginSharedPtr& plugin,
                                                   Event::Dispatcher& dispatcher) {
  if (!base_wasm) {
    if (!plugin->fail_open_) {
      ENVOY_LOG_TO_LOGGER(Envoy::Logger::Registry::getLog(Envoy::Logger::Id::wasm), critical,
                          "Plugin configured to fail closed failed to load");
    }
    // To handle the case when failed to create VMs and fail-open/close properly,
    // we still create PluginHandle with null WasmBase.
    return std::make_shared<PluginHandle>(nullptr, plugin);
  }
  return std::static_pointer_cast<PluginHandle>(Host::getOrCreateThreadLocalPlugin(
      std::static_pointer_cast<WasmHandle>(base_wasm), plugin,
      getWasmHandleCloneFactory(dispatcher), /*, create_root_context_for_testing),*/
      getPluginHandleFactory()));
  return nullptr;
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
