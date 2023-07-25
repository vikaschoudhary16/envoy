load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "http_wasm_lib",
    srcs = [
        "context.cc",
        "plugin.cc",
        "vm.cc",
        "vm_runtime.cc",
        "wasm_filter.cc",
    ],
    hdrs = [
        "context.h",
        "plugin.h",
        "vm.h",
        "vm_runtime.h",
        "wasm_filter.h",
        "wasm_runtime_factory.h",
    ],
    deps = [
        "//contrib/http_wasm/filters/http/source/host:http_wasm_cpp_host_lib",
        "//envoy/http:codes_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/server:lifecycle_notifier_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/extensions/common/wasm:wasm_hdr",
        "//source/extensions/common/wasm:wasm_lib",
        "@envoy_api//contrib/envoy/extensions/filters/http/http_wasm/v3alpha:pkg_cc_proto",
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = [
        "config.h",
    ],
    deps = [
        ":http_wasm_lib",
        "//envoy/registry",
        "//source/common/common:empty_string",
        "//source/common/config:datasource_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/http/http_wasm/v3alpha:pkg_cc_proto",
    ],
)
