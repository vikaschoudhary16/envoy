/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Intrinsic enumerations available to WASM modules.
 */
// NOLINT(namespace-envoy)
#pragma once

#include <cstdint>

enum class LogLevel : int32_t { debug = -1, info, warn, error, none, Max = none };
enum class FilterStatus : int32_t { Continue = 0, StopIteration = 1 };
enum class FilterHeadersStatus : int32_t {
  StopIteration = 0,
  Continue = 1,
};
enum class FilterMetadataStatus : int32_t { Continue = 0 };
enum class FilterTrailersStatus : int32_t { Continue = 0, StopIteration = 1 };
enum class FilterDataStatus : int32_t {
  StopIteration = 0,
  Continue = 1,
};
