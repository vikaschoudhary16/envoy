load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_contrib_extension(
    name = "http_wasm_cpp_host_lib",
    srcs = [
        "bytecode_util.cc",
        "context.cc",
        "exports.cc",
        "vm.cc",
    ],
    hdrs = [
        "bytecode_util.h",
        "context.h",
        "context_interface.h",
        "exports.h",
        "http_wasm_common.h",
        "http_wasm_enums.h",
        "vm.h",
        "vm_runtime.h",
        "word.h",
    ],
    deps = [
    ],
)

envoy_cc_library(
    name = "v8_lib",
    srcs = [
        "src/v8/v8.cc",
    ],
    hdrs = [
        "context.h",
        "context_interface.h",
        "http_wasm_common.h",
        "http_wasm_enums.h",
        "v8.h",
        "vm_runtime.h",
        "word.h",
    ],
    copts = [
        "-DWAVM_API=",
        "-Wno-non-virtual-dtor",
        "-Wno-old-style-cast",
    ],
    deps = [
        "//external:wee8",
    ],
)
