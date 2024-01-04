load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "wasm_filter_lib",
    srcs = ["filter.cc"],
    hdrs = ["filter.h"],
    copts = [
        "-Wno-error",
    ],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/extensions/common/http_wasm:http_wasm_lib",
        "@envoy_api//envoy/extensions/filters/http/wasm/v3:pkg_cc_proto",
    ],
    alwayslink = 1,
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    copts = [
        "-Wno-error",
    ],
    deps = [
        ":wasm_filter_lib",
        "//envoy/registry",
        "//source/common/common:empty_string",
        "//source/common/config:datasource_lib",
        "//source/extensions/common/http_wasm:http_wasm_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/wasm/v3:pkg_cc_proto",
    ],
)
