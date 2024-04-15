/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
  return std::make_unique<envoy::listener::kmesh_tlv::config::KmeshTlv>();
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
