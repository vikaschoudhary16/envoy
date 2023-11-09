load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)
# load(
#     "//bazel:envoy_select.bzl",
#     "envoy_select_wasm_cpp_tests",
# )

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "config_test",
    size = "enormous",
    srcs = ["config_test.cc"],
    data = [
        "//test/extensions/filters/http/http_wasm/test_data/req-header:envoy-tests.wasm",
    ],
    extension_names = ["envoy.filters.http.http_wasm"],
    deps = [
        "//source/common/common:base64_lib",
        "//source/common/common:hex_lib",
        "//source/common/crypto:utility_lib",
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/http_wasm:config",
        "//source/extensions/filters/http/http_wasm:wasm_filter_lib",
        "//test/mocks/server:server_mocks",
        "//test/test_common:environment_lib",
        "@envoy_api//envoy/extensions/filters/http/http_wasm/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "wasm_filter_test",
    size = "enormous",
    srcs = ["wasm_filter_test.cc"],
    data = [
        "//test/extensions/filters/http/http_wasm/test_data/req-header:envoy-tests.wasm",
    ],
    extension_names = ["envoy.filters.http.http_wasm"],
    deps = [
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/http_wasm:wasm_filter_lib",
        "//test/mocks/network:connection_mocks",
        "//test/mocks/router:router_mocks",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:wasm_lib",
    ],
)
