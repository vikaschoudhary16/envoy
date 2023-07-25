load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)
load("//bazel:envoy_select.bzl", "envoy_select_wasm_v8")

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    srcs = envoy_select_wasm_v8(["config.cc"]),
    deps = envoy_select_wasm_v8([
        "//envoy/registry",
        "//contrib/http_wasm/filters/http/source:http_wasm_lib",
        "//contrib/http_wasm/filters/http/source/host:v8_lib",
        "//contrib/http_wasm/filters/http/source/host:http_wasm_cpp_host_lib",
    ]),
)
