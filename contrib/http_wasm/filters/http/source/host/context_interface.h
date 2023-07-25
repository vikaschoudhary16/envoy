#pragma once

#include <time.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <optional>
#include <map>
#include <memory>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace Host {

#include "contrib/http_wasm/filters/http/source/host/http_wasm_common.h"
#include "contrib/http_wasm/filters/http/source/host/http_wasm_enums.h"

struct PluginBase;
class WasmBase;

/**
 * BufferInterface provides a interface between proxy-specific buffers and the proxy-independent ABI
 * implementation. Embedders should subclass BufferInterface to enable the proxy-independent code to
 * implement ABI calls which use buffers (e.g. the HTTP body).
 */
struct BufferInterface {
  virtual ~BufferInterface() = default;
  virtual size_t size() const = 0;
  /**
   * @param ptr_ptr is the location in the VM address space to place the address of the newly
   * allocated memory block which contains the copied bytes.
   * @param size_ptr is the location in the VM address space to place the size of the newly
   * allocated memory block which contains the copied bytes (i.e. length).
   * @return a WasmResult with any error or WasmResult::Ok.
   */
  virtual int64_t copyTo(void* ptr_ptr, uint64_t size_ptr) = 0;

  /**
   * Copy (alias) bytes from the VM 'data' into the buffer, replacing the provided range..
   * @param start is the first buffer byte to replace.
   * @param length is the length of sequence of buffer bytes to replace.
   * @param data the data to copy over the replaced region.
   * @return a WasmResult with any error or WasmResult::Ok.
   */
  virtual WasmResult copyFrom(size_t start, std::string_view data, size_t length) = 0;
};

/**
 * RootInterface is the interface specific to RootContexts.
 * A RootContext is associated with one more more plugins and is the parent of all stream Context(s)
 * created for that plugin. It can be used to store data shared between stream Context(s) in the
 * same VM.
 */
struct RootInterface {
  virtual ~RootInterface() = default;
  /**
   * Call on a host Context to create a corresponding Context in the VM.  Note:
   * onNetworkNewConnection and onRequestHeaders() call onCreate().
   * stream Context this will be a Root Context id (or sub-Context thereof).
   */
  virtual void onCreate() = 0;

  /**
   * Call on a Root Context when a VM first starts up.
   * @param plugin is the plugin which caused the VM to be started.
   * Called by the host code.
   */
  virtual bool onStart(std::shared_ptr<PluginBase> plugin) = 0;

  /**
   * Call when a stream has completed (both sides have closed) or on a Root Context when the VM is
   * shutting down.
   * @return true for stream contexts or for Root Context(s) if the VM can shutdown, false for Root
   * Context(s) if the VM should wait until the Root Context calls the proxy_done() ABI call.  Note:
   * the VM may (std::optionally) shutdown after some configured timeout even if the Root Context
   * does not call proxy_done().
   */
  virtual bool onDone() = 0;

  // Call for logging not associated with a stream lifecycle (e.g. logging only plugin).
  virtual void onLog() = 0;

  /**
   * Call when no further stream calls will occur.  This will cause the corresponding Context in the
   * VM to be deleted.
   * Called by the host code.
   */
  virtual void onDelete() = 0;
};

/**
 * HttpInterface is the interface between the VM host and the VM for HTTP streams.
 */
struct HttpInterface {
public:
  virtual ~HttpInterface() = default;
  /**
   * Call on a stream context to indicate that the request headers have arrived.  Calls
   * onCreate() to create a Context in the VM first.
   */
  virtual FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) = 0;

  // Call on a stream context to indicate that body data has arrived.
  virtual FilterDataStatus onRequestBody(uint32_t body_length, bool end_of_stream) = 0;

  // Call on a stream context to indicate that the request trailers have arrived.
  virtual FilterTrailersStatus onRequestTrailers(uint32_t trailers) = 0;

  // Call on a stream context to indicate that the request metadata has arrived.
  virtual FilterMetadataStatus onRequestMetadata(uint32_t elements) = 0;

  // Call on a stream context to indicate that the request trailers have arrived.
  virtual FilterHeadersStatus onResponseHeaders(uint32_t trailers, bool end_of_stream) = 0;

  // Call on a stream context to indicate that body data has arrived.
  virtual FilterDataStatus onResponseBody(uint32_t body_length, bool end_of_stream) = 0;

  // Call on a stream context to indicate that the request trailers have arrived.
  virtual FilterTrailersStatus onResponseTrailers(uint32_t trailers) = 0;

  // Call on a stream context to indicate that the request metadata has arrived.
  virtual FilterMetadataStatus onResponseMetadata(uint32_t elements) = 0;

  // Call when the stream closes. See RootInterface.
  virtual bool onDone() = 0;

  // Call when the stream status has finalized, e.g. for logging. See RootInterface.
  virtual void onLog() = 0;

  // Call just before the Context is deleted. See RootInterface.
  virtual void onDelete() = 0;

  /**
   * Respond directly to an HTTP request.
   * @param response_code is the response code to send.
   */
  virtual void sendLocalResponse(uint32_t response_code) = 0;

  /**
   * Provides a BufferInterface to be used to return buffered data to the VM.
   * @param type is the type of buffer to provide.
   */
  virtual const BufferInterface* getBuffer(WasmBufferType type) = 0;
};

// Header/Trailer/Metadata Maps
struct HeaderInterface {
  virtual ~HeaderInterface() = default;
  /**
   * Add a key-value pair to a header map.
   * @param type of the header map.
   * @param key is the key (header).
   * @param value is the value (header value).
   */
  virtual WasmResult addHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                       std::string_view value) = 0;

  /**
   * Get a value from to a header map.
   * @param type of the header map.
   * @param key is the key (header).
   * @param result is a pointer to the returned header value.
   */
  virtual WasmResult getHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                       std::string_view* result) = 0;

  /**
   * Remove a key-value pair from a header map.
   * @param type of the header map.
   * @param key of the header map.
   */
  virtual WasmResult removeHeaderMapValue(WasmHeaderMapType type, std::string_view key) = 0;

  /**
   * Replace (or set) a value in a header map.
   * @param type of the header map.
   * @param key of the header map.
   * @param value to set in the header map.
   */
  virtual WasmResult replaceHeaderMapValue(WasmHeaderMapType type, std::string_view key,
                                           std::string_view value) = 0;

  /**
   * Returns the number of entries in a header map.
   * @param type of the header map.
   * @param result is a pointer to the result.
   */
  virtual WasmResult getHeaderMapSize(WasmHeaderMapType type, uint32_t* result) = 0;
};

struct GeneralInterface {
  virtual ~GeneralInterface() = default;
  /**
   * Will be called on severe Wasm errors. Callees may report and handle the error (e.g. via an
   * Exception) to prevent the proxy from crashing.
   */
  virtual void error(std::string_view message) = 0;

  /**
   * Called by all functions which are not overridden with a proxy-specific implementation.
   * @return WasmResult::Unimplemented.
   */
  virtual WasmResult unimplemented() = 0;

  // Log a message.
  virtual WasmResult log(uint32_t level, std::string_view message) = 0;

  // Return the current log level in the host
  virtual uint32_t getLogLevel() = 0;

  // Provides the current time in nanoseconds since the Unix epoch.
  virtual uint64_t getCurrentTimeNanoseconds() = 0;

  // Provides the monotonic time in nanoseconds.
  virtual uint64_t getMonotonicTimeNanoseconds() = 0;

  // Returns plugin configuration.
  virtual std::string_view getConfiguration() = 0;
};

} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
