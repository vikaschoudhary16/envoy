load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)
load(
    "//bazel:envoy_select.bzl",
    "envoy_select_wasm_rust_tests",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "vm_runtime_test",
    size = "enormous",
    srcs = ["vm_runtime_test.cc"],
    data = envoy_select_wasm_rust_tests([
        "//test/extensions/common/http_wasm/test_data:test_rust.wasm",
    ]),
    shard_count = 50,
    deps = [
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/http_wasm:wasm_filter_lib",
    ],
)
