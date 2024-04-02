#include <string>

#include "echo2.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the kmesh tls listener filter. @see NamedListenerFilterConfigFactory.
 */
class KmeshTlvConfigFactory : public NamedListenerFilterConfigFactory {
public:
  Network::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message&,
                                                        FactoryContext&) override {
    return [](Network::FilterManager& filter_manager) -> void {
      filter_manager.addReadFilter(Network::ReadFilterSharedPtr{new Filter::Echo2()});
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Struct()};
  }

  std::string name() const override { return "envoy.filters.listener.kmesh_tlv"; }

  bool isTerminalFilterByProto(const Protobuf::Message&, ServerFactoryContext&) override {
    return "true";
  }
};

/**
 * Static registration for the kmesh tlv listener filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<KmeshTlvConfigFactory, NamedNetworkFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
