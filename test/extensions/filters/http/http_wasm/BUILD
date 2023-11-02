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

# envoy_extension_cc_test(
#     name = "vm_runtime_test",
#     size = "enormous",
#     srcs = ["vm_runtime_test.cc"],
#     data = envoy_select_wasm_rust_tests([
#         "//test/extensions/common/wasm/test_data:test_rust.wasm",
#     ]),
#     extension_names = ["envoy.filters.http.http_wasm"],
#     shard_count = 50,
#     deps = [
#         "//source/common/http:message_lib",
#         "//source/extensions/filters/http/http_wasm:wasm_filter_lib",
#     ],
# )

envoy_extension_cc_test(
    name = "wasm_filter_test",
    size = "enormous",
    srcs = ["wasm_filter_test.cc"],
    # data = [
    #     "//test/extensions/filters/http/http_wasm/test_data:main.wasm-7oct",
    # ],
    # data = envoy_select_wasm_cpp_tests([
    #     "//test/extensions/filters/http/http_wasm/test_data:test_cpp.wasm",
    # ]),
    # ]) + envoy_select_wasm_rust_tests([
    #     "//test/extensions/filters/http/wasm/test_data:async_call_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:body_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:close_stream_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:grpc_call_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:grpc_stream_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:headers_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:metadata_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:panic_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:resume_call_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:shared_data_rust.wasm",
    #     "//test/extensions/filters/http/wasm/test_data:shared_queue_rust.wasm",
    # ]),
    extension_names = ["envoy.filters.http.http_wasm"],
    shard_count = 50,
    deps = [
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/http_wasm:wasm_filter_lib",
        "//test/mocks/network:connection_mocks",
        "//test/mocks/router:router_mocks",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:wasm_lib",
    ],
)
