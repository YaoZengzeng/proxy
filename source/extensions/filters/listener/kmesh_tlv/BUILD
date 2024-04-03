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
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/common/network:filter_state_dst_address_lib",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["kmesh_tlv_config_factory.cc"],
    hdrs = ["kmesh_tlv_config_factory.h"],
    repository = "@envoy",
    deps = [
        ":kmesh_tlv_lib",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry:registry",
        "@envoy//envoy/server:filter_config_interface",
    ],
)
