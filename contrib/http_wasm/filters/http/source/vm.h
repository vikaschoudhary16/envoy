#pragma once

#include "contrib/http_wasm/filters/http/source/plugin.h"
#include "contrib/http_wasm/filters/http/source/context.h"
#include "contrib/http_wasm/filters/http/source/host/context.h"
#include "envoy/server/lifecycle_notifier.h"
#include "host/vm_runtime.h"
#include "source/common/config/datasource.h"
#include "source/extensions/common/wasm/stats_handler.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
using Common::Wasm::WasmEvent;
using Host::FailState;

class WasmHandle;

class Wasm : public Host::WasmBase, Logger::Loggable<Logger::Id::wasm> {
public:
  Wasm(WasmConfig& config, absl::string_view vm_key, const Stats::ScopeSharedPtr& scope,
       Api::Api& api, Upstream::ClusterManager& cluster_manager, Event::Dispatcher& dispatcher);
  Wasm(std::shared_ptr<WasmHandle> other, Event::Dispatcher& dispatcher);
  ~Wasm() override;

  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  Event::Dispatcher& dispatcher() { return dispatcher_; }
  Api::Api& api() { return api_; }
  Context* getRootContext() { return static_cast<Context*>(WasmBase::getRootContext()); }
  std::shared_ptr<Wasm> sharedThis() { return std::static_pointer_cast<Wasm>(shared_from_this()); }

  // WasmBase
  void error(std::string_view message) override;
  ContextBase* createContext(const std::shared_ptr<Host::PluginBase>& plugin) override;
  ContextBase* createRootContext(const std::shared_ptr<Host::PluginBase>& plugin) override;
  void registerCallbacks() override;
  void getFunctions() override;

  // AccessLog::Instance
  void log(const PluginSharedPtr& plugin, const Http::RequestHeaderMap* request_headers,
           const Http::ResponseHeaderMap* response_headers,
           const Http::ResponseTrailerMap* response_trailers,
           const StreamInfo::StreamInfo& stream_info, AccessLog::AccessLogType access_log_type);

  void initializeLifecycle(Server::ServerLifecycleNotifier& lifecycle_notifier);

protected:
  friend class Context;

  Stats::ScopeSharedPtr scope_;
  Api::Api& api_;
  Stats::StatNamePool stat_name_pool_;
  const Stats::StatName custom_stat_namespace_;
  Upstream::ClusterManager& cluster_manager_;
  Event::Dispatcher& dispatcher_;
  Event::PostCb server_shutdown_post_cb_;
  absl::flat_hash_map<uint32_t, Event::TimerPtr> timer_; // per root_id.
  TimeSource& time_source_;

  // // Lifecycle stats
  Common::Wasm::LifecycleStatsHandler lifecycle_stats_handler_;
};
using WasmSharedPtr = std::shared_ptr<Wasm>;

class WasmHandle : public Host::WasmHandleBase, public ThreadLocal::ThreadLocalObject {
public:
  explicit WasmHandle(const WasmSharedPtr& wasm)
      : Host::WasmHandleBase(std::static_pointer_cast<Host::WasmBase>(wasm)), wasm_(wasm) {}

  WasmSharedPtr& wasm() { return wasm_; }

private:
  WasmSharedPtr wasm_;
};
using WasmHandleSharedPtr = std::shared_ptr<WasmHandle>;

class PluginHandle : public Host::PluginHandleBase {
public:
  explicit PluginHandle(const WasmHandleSharedPtr& wasm_handle, const PluginSharedPtr& plugin)
      : Host::PluginHandleBase(std::static_pointer_cast<Host::WasmHandleBase>(wasm_handle),
                               std::static_pointer_cast<Host::PluginBase>(plugin)),
        plugin_(plugin), wasm_handle_(wasm_handle) {}

  WasmHandleSharedPtr& wasmHandle() { return wasm_handle_; }
  uint32_t rootContextId() { return wasm_handle_->wasm()->getRootContext()->id(); }

private:
  PluginSharedPtr plugin_;
  WasmHandleSharedPtr wasm_handle_;
};

using PluginHandleSharedPtr = std::shared_ptr<PluginHandle>;
class PluginHandleSharedPtrThreadLocal : public ThreadLocal::ThreadLocalObject {
public:
  PluginHandleSharedPtrThreadLocal(PluginHandleSharedPtr handle) : handle_(handle){};
  PluginHandleSharedPtr& handle() { return handle_; }

private:
  PluginHandleSharedPtr handle_;
};

using CreateWasmCallback = std::function<void(WasmHandleSharedPtr)>;
// Returns false if createWasm failed synchronously. This is necessary because xDS *MUST* report
// all failures synchronously as it has no facility to report configuration update failures
// asynchronously. Callers should throw an exception if they are part of a synchronous xDS update
// because that is the mechanism for reporting configuration errors.
bool createWasm(const PluginSharedPtr& plugin, const Stats::ScopeSharedPtr& scope,
                Upstream::ClusterManager& cluster_manager, Init::Manager& init_manager,
                Event::Dispatcher& dispatcher, Api::Api& api,
                Envoy::Server::ServerLifecycleNotifier& lifecycle_notifier,
                Config::DataSource::RemoteAsyncDataProviderPtr& remote_data_provider,
                CreateWasmCallback&& callback);

PluginHandleSharedPtr getOrCreateThreadLocalPlugin(const WasmHandleSharedPtr& base_wasm,
                                                   const PluginSharedPtr& plugin,
                                                   Event::Dispatcher& dispatcher);
WasmEvent toWasmEvent(const std::shared_ptr<WasmHandleBase>& wasm);

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
