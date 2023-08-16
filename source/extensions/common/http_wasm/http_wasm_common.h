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
  // A protobuf could not be parsed.
  ParseFailure = 4,
  // A provided expression (e.g. "foo.bar") was illegal or unrecognized.
  BadExpression = 5,
  // A provided memory range was not legal.
  InvalidMemoryAccess = 6,
  // Data was requested from an empty container.
  Empty = 7,
  // The provided CAS did not match that of the stored data.
  CasMismatch = 8,
  // Returned result was unexpected, e.g. of the incorrect size.
  ResultMismatch = 9,
  // Internal failure: trying check logs of the surrounding system.
  InternalFailure = 10,
  // Feature not implemented.
  Unimplemented = 12,
};

#define _CASE(_e)                                                                                  \
  case WasmResult::_e:                                                                             \
    return #_e
inline std::string toString(WasmResult r) {
  switch (r) {
    _CASE(Ok);
    _CASE(NotFound);
    _CASE(BadArgument);
    _CASE(ParseFailure);
    _CASE(BadExpression);
    _CASE(InvalidMemoryAccess);
    _CASE(Empty);
    _CASE(CasMismatch);
    _CASE(ResultMismatch);
    _CASE(InternalFailure);
    _CASE(Unimplemented);
  }
  return "Unknown";
}
#undef _CASE

enum class WasmHeaderMapType : int32_t {
  RequestHeaders = 0,
  ResponseHeaders = 1,
  RequestTrailers = 2,
  ResponseTrailers = 3,
  MAX = 3,
};
enum class WasmBufferType : int32_t {
  HttpRequestBody = 0,
  HttpResponseBody = 1,
  MAX = 1,
};
enum class WasmBufferFlags : int32_t {
  // These must be powers of 2.
  EndOfStream = 1,
};
enum class WasmStreamType : int32_t {
  Request = 0,
  Response = 1,
  MAX = 1,
};
