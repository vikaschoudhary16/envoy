#pragma once

#include <cstdint>
#include <string>

enum class WasmResult : uint32_t {
  Ok = 0,
  // The result could not be found, e.g. a provided key did not appear in a
  // table.
  NotFound = 1,
  // An argument was bad, e.g. did not not conform to the required range.
  BadArgument = 2,
};

enum class WasmHeaderMapType : int32_t {
  RequestHeaders = 0,
  ResponseHeaders = 1,
  MAX = 3,
};
enum class WasmBufferType : int32_t {
  HttpRequestBody = 0,
  HttpResponseBody = 1,
  MAX = 1,
};
