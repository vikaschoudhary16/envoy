load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "v8_lib",
    srcs = ["v8.cc"],
    hdrs = ["v8.h"],
    external_deps = [
        "wee8",
    ],
    deps = [
        # "//contrib/http_wasm/filters/http/source:exports_lib",
        "//contrib/http_wasm/filters/http/source:runtime_interface",
        "//contrib/http_wasm/filters/http/source:wasm_hdr",
        "//source/common/common:assert_lib",
    ],
)
