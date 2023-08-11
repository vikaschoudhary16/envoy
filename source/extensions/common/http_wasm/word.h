#pragma once

#include <iostream>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

#include "source/extensions/common/http_wasm/http_wasm_common.h"

// Use byteswap functions only when compiling for big-endian platforms.
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                                    \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htowasm(x, vm_uses_wasm_byte_order) ((vm_uses_wasm_byte_order) ? __builtin_bswap32(x) : (x))
#define wasmtoh(x, vm_uses_wasm_byte_order) ((vm_uses_wasm_byte_order) ? __builtin_bswap32(x) : (x))
#else
#define htowasm(x, vm_uses_wasm_byte_order) (x)
#define wasmtoh(x, vm_uses_wasm_byte_order) (x)
#endif

// Represents a Wasm-native word-sized datum. On 32-bit VMs, the high bits are always zero.
// The Wasm/VM API treats all bits as significant.
struct Word {
  Word() : u64_(0) {}
  Word(uint64_t w) : u64_(w) {}                          // Implicit conversion into Word.
  Word(WasmResult r) : u64_(static_cast<uint64_t>(r)) {} // Implicit conversion into Word.
  uint32_t u32() const { return static_cast<uint32_t>(u64_); }
  operator uint64_t() const { return u64_; }
  uint64_t u64_;
};

// Convert Word type for use by 32-bit VMs.
template <typename T> struct ConvertWordTypeToUint32 {
  using type = T; // NOLINT(readability-identifier-naming)
};
template <> struct ConvertWordTypeToUint32<Word> {
  using type = uint32_t; // NOLINT(readability-identifier-naming)
};

// Convert Word-based function types for 32-bit VMs.
template <typename F> struct ConvertFunctionTypeWordToUint32 {};
template <typename R, typename... Args> struct ConvertFunctionTypeWordToUint32<R (*)(Args...)> {
  using type = typename ConvertWordTypeToUint32<R>::type (*)(
      typename ConvertWordTypeToUint32<Args>::type...);
};

template <typename T> inline auto convertWordToUint32(T t) { return t; }
template <> inline auto convertWordToUint32<Word>(Word t) { return static_cast<uint32_t>(t.u64_); }

// Convert a function of the form Word(Word...) to one of the form uint32_t(uint32_t...).
template <typename F, F* fn> struct ConvertFunctionWordToUint32 {
  static void convertFunctionWordToUint32() {}
};
template <typename R, typename... Args, auto(*F)(Args...)->R>
struct ConvertFunctionWordToUint32<R(Args...), F> {
  static typename ConvertWordTypeToUint32<R>::type
  convertFunctionWordToUint32(typename ConvertWordTypeToUint32<Args>::type... args) {
    return convertWordToUint32(F(std::forward<Args>(args)...));
  }
};
template <typename... Args, auto(*F)(Args...)->void>
struct ConvertFunctionWordToUint32<void(Args...), F> {
  static void convertFunctionWordToUint32(typename ConvertWordTypeToUint32<Args>::type... args) {
    F(std::forward<Args>(args)...);
  }
};

inline std::ostream& operator<<(std::ostream& os, const Word& w) { return os << w.u64_; }
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
