#pragma once

#include "kmesh_tlv.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "source/extensions/filters/listener/kmesh_tlv/config/kmesh_tlv.pb.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {
/**
 * Config registration for the kmesh tlv filter.
 */
class KmeshTlvConfigFactory : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& message,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override { return "envoy.filters.listener.kmesh_tlv"; }
};

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
