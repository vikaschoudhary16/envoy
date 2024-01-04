load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "http_wasm_lib",
    srcs = [
        "bytecode_util.cc",
        "context.cc",
        "exports.cc",
        "guest.cc",
        "guest_config.cc",
        "vm_runtime.cc",
    ],
    hdrs = [
        "exports.h",
    ],
    copts = [
        "-Wno-error",
    ],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/server:lifecycle_notifier_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/common/http:header_map_lib",
        "//source/common/http:message_lib",
        "//source/common/http:utility_lib",
        "//source/common/tracing:http_tracer_lib",
        "//source/extensions/common/http_wasm:runtime_interface",
        "//source/extensions/common/http_wasm:wasm_hdr",
        "//source/extensions/common/http_wasm/v8:v8_lib",
        "//source/extensions/filters/common/expr:context_lib",
        "@envoy_api//envoy/extensions/filters/http/http_wasm/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "wasm_hdr",
    hdrs = [
        "bytecode_util.h",
        "context.h",
        "guest.h",
        "guest_config.h",
        "vm_runtime.h",
    ],
    copts = [
        "-Wno-error",
    ],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/server:lifecycle_notifier_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/buffer:buffer_lib",
        "@envoy_api//envoy/extensions/filters/http/http_wasm/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = [
        "config.h",
    ],
    copts = [
        "-Wno-error",
    ],
    deps = [
        ":http_wasm_lib",
        "//envoy/registry",
        "//source/common/common:empty_string",
        "//source/common/config:datasource_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/http_wasm/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "runtime_interface",
    hdrs = [
        "http_wasm_common.h",
        "http_wasm_enums.h",
        "vm_runtime.h",
        "word.h",
    ],
    copts = [
        "-Wno-error",
    ],
    external_deps = ["abseil_optional"],
    deps = [
        "//source/common/common:minimal_logger_lib",
        "//source/common/stats:stats_lib",
    ],
)
