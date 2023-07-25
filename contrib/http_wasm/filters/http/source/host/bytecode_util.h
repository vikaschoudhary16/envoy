#pragma once

#include <string_view>
#include <vector>
#include <unordered_map>

#include "contrib/http_wasm/filters/http/source/host/vm_runtime.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
namespace Host {

// Utilitiy functions which directly operate on Wasm bytecodes.
class BytecodeUtil {
public:
  /**
   * checkWasmHeader validates Wasm header.
   * @param bytecode is the target bytecode.
   * @return indicates whether the bytecode has valid Wasm header.
   */
  static bool checkWasmHeader(std::string_view bytecode);

  /**
   * getCustomSection extract the view of the custom section for a given name.
   * @param bytecode is the target bytecode.
   * @param name is the name of the custom section.
   * @param ret is the reference to store the resulting view to the custom section.
   * @return indicates whether parsing succeeded or not.
   */
  static bool getCustomSection(std::string_view bytecode, std::string_view name,
                               std::string_view& ret);

  /**
   * getFunctionNameIndex constructs the map from function indexes to function names stored in
   * the function name subsection in "name" custom section.
   * See https://webassembly.github.io/spec/core/appendix/custom.html#binary-funcnamesec for detail.
   * @param bytecode is the target bytecode.
   * @param ret is the reference to store map from function indexes to function names.
   * @return indicates whether parsing succeeded or not.
   */
  static bool getFunctionNameIndex(std::string_view bytecode,
                                   std::unordered_map<uint32_t, std::string>& ret);

  /**
   * getStrippedSource gets Wasm module without Custom Sections to save some memory in workers.
   * @param bytecode is the original bytecode.
   * @param ret is the reference to the stripped bytecode or a copy of the original bytecode.
   * @return indicates whether parsing succeeded or not.
   */
  static bool getStrippedSource(std::string_view bytecode, std::string& ret);

private:
  static bool parseVarint(const char*& pos, const char* end, uint32_t& ret);
};
} // namespace Host
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
