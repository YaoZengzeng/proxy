#include "kmesh_tlv_config_factory.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

Network::ListenerFilterFactoryCb KmeshTlvConfigFactory::createListenerFilterFactoryFromProto(
    const Protobuf::Message&,
    const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
    Server::Configuration::ListenerFactoryContext&) {
  return [listener_filter_matcher](Network::ListenerFilterManager& filter_manager) -> void {
    filter_manager.addAcceptFilter(listener_filter_matcher, std::make_unique<KmeshTlvFilter>());
  };
}

ProtobufTypes::MessagePtr KmeshTlvConfigFactory::createEmptyConfigProto() {
  return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Struct()};
}
/**
 * Static registration for the kmesh tlv filter. @see RegisterFactory.
 */
REGISTER_FACTORY(KmeshTlvConfigFactory, Server::Configuration::NamedListenerFilterConfigFactory){
    "envoy.listener.kmesh_tlv"};

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
