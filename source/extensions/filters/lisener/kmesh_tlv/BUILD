load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "kmesh_tlv_lib",
    srcs = ["kmesh_tlv.cc"],
    hdrs = ["kmesh_tlv.h"],
    repository = "@envoy",
    visibility = ["//visibility:public""],
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
    ],
)

envoy_cc_library(
    name = "config"
    srcs = ["config.cc"]
    repository = "@envoy",
    deps = [
        ":kmesh_tlv_lib",
        "@envoy//envoy/registry:registry"
    ]
)
