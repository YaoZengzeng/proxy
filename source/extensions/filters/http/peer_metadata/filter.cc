// Copyright Istio Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "source/extensions/filters/http/peer_metadata/filter.h"

#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "extensions/common/context.h"
#include "extensions/common/metadata_object.h"
#include "extensions/common/proto_util.h"
#include "source/common/common/hash.h"
#include "source/common/common/base64.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/network/utility.h"
#include "source/extensions/filters/common/expr/cel_state.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PeerMetadata {

// Extended peer info that supports "hashing" to enable sharing with the
// upstream connection via an internal listener.
class CelStateHashable : public Filters::Common::Expr::CelState, public Hashable {
public:
  explicit CelStateHashable(const Filters::Common::Expr::CelStatePrototype& proto)
      : CelState(proto) {}
  absl::optional<uint64_t> hash() const override { return HashUtil::xxHash64(value()); }
};

struct CelPrototypeValues {
  const Filters::Common::Expr::CelStatePrototype NodeInfo{
      true, Filters::Common::Expr::CelStateType::FlatBuffers,
      toAbslStringView(Wasm::Common::nodeInfoSchema()),
      // Life span is only needed for Wasm set_property, not in the native filters.
      StreamInfo::FilterState::LifeSpan::FilterChain};
  const Filters::Common::Expr::CelStatePrototype NodeId{
      true, Filters::Common::Expr::CelStateType::String, absl::string_view(),
      // Life span is only needed for Wasm set_property, not in the native filters.
      StreamInfo::FilterState::LifeSpan::FilterChain};
};

using CelPrototypes = ConstSingleton<CelPrototypeValues>;

class XDSMethod : public DiscoveryMethod {
public:
  XDSMethod(bool downstream, Server::Configuration::ServerFactoryContext& factory_context)
      : downstream_(downstream),
        // 构建metadata provider
        metadata_provider_(Extensions::Common::WorkloadDiscovery::GetProvider(factory_context)) {}
  absl::optional<PeerInfo> derivePeerInfo(const StreamInfo::StreamInfo&, Http::HeaderMap&,
                                          Context&) const override;

private:
  const bool downstream_;
  Extensions::Common::WorkloadDiscovery::WorkloadMetadataProviderSharedPtr metadata_provider_;
};

absl::optional<PeerInfo> XDSMethod::derivePeerInfo(const StreamInfo::StreamInfo& info,
                                                   Http::HeaderMap&, Context&) const {
  if (!metadata_provider_) {
    return {};
  }
  Network::Address::InstanceConstSharedPtr peer_address;
  if (downstream_) {
    // 获取peer address
    peer_address = info.downstreamAddressProvider().remoteAddress();
  } else {
    if (info.upstreamInfo().has_value()) {
      // 获取upstream host
      auto upstream_host = info.upstreamInfo().value().get().upstreamHost();
      if (upstream_host) {
        const auto address = upstream_host->address();
        switch (address->type()) {
        case Network::Address::Type::Ip:
          peer_address = upstream_host->address();
          break;
        case Network::Address::Type::EnvoyInternal:
          if (upstream_host->metadata()) {
            const auto& filter_metadata = upstream_host->metadata()->filter_metadata();
            // 从filter metadata获取original dst
            const auto& it = filter_metadata.find("envoy.filters.listener.original_dst");
            if (it != filter_metadata.end()) {
              const auto& destination_it = it->second.fields().find("local");
              if (destination_it != it->second.fields().end()) {
                peer_address = Network::Utility::parseInternetAddressAndPortNoThrow(
                    destination_it->second.string_value(), /*v6only=*/false);
              }
            }
          }
          break;
        default:
          break;
        }
      }
    }
  }
  // 用peer address获取metadata
  const auto metadata_object = metadata_provider_->GetMetadata(peer_address);
  if (metadata_object) {
    // 将workload metadata转换为flat node
    return Istio::Common::convertWorkloadMetadataToFlatNode(metadata_object.value());
  }
  return {};
}

MXMethod::MXMethod(bool downstream, Server::Configuration::ServerFactoryContext& factory_context)
    : downstream_(downstream), tls_(factory_context.threadLocal()) {
  tls_.set([](Event::Dispatcher&) { return std::make_shared<MXCache>(); });
}

absl::optional<PeerInfo> MXMethod::derivePeerInfo(const StreamInfo::StreamInfo&,
                                                  Http::HeaderMap& headers, Context& ctx) const {
  const auto peer_id_header = headers.get(Headers::get().ExchangeMetadataHeaderId);
  if (downstream_) {
    ctx.request_peer_id_received_ = !peer_id_header.empty();
  }
  absl::string_view peer_id =
      peer_id_header.empty() ? "" : peer_id_header[0]->value().getStringView();
  const auto peer_info_header = headers.get(Headers::get().ExchangeMetadataHeader);
  if (downstream_) {
    ctx.request_peer_received_ = !peer_info_header.empty();
  }
  absl::string_view peer_info =
      peer_info_header.empty() ? "" : peer_info_header[0]->value().getStringView();
  if (!peer_info.empty()) {
    return lookup(peer_id, peer_info);
  }
  return {};
}

void MXMethod::remove(Http::HeaderMap& headers) const {
  headers.remove(Headers::get().ExchangeMetadataHeaderId);
  headers.remove(Headers::get().ExchangeMetadataHeader);
}

absl::optional<PeerInfo> MXMethod::lookup(absl::string_view id, absl::string_view value) const {
  // This code is copied from:
  // https://github.com/istio/proxy/blob/release-1.18/extensions/metadata_exchange/plugin.cc#L116
  auto& cache = tls_->cache_;
  if (max_peer_cache_size_ > 0 && !id.empty()) {
    auto it = cache.find(id);
    if (it != cache.end()) {
      return it->second;
    }
  }
  const auto bytes = Base64::decodeWithoutPadding(value);
  google::protobuf::Struct metadata;
  if (!metadata.ParseFromString(bytes)) {
    return {};
  }
  const auto fb = ::Wasm::Common::extractNodeFlatBufferFromStruct(metadata);
  std::string out(reinterpret_cast<const char*>(fb.data()), fb.size());
  if (max_peer_cache_size_ > 0 && !id.empty()) {
    // do not let the cache grow beyond max cache size.
    if (static_cast<uint32_t>(cache.size()) > max_peer_cache_size_) {
      cache.erase(cache.begin(), std::next(cache.begin(), max_peer_cache_size_ / 4));
    }
    cache.emplace(id, out);
  }
  return out;
}

MXPropagationMethod::MXPropagationMethod(
    bool downstream, Server::Configuration::ServerFactoryContext& factory_context,
    const io::istio::http::peer_metadata::Config_IstioHeaders& istio_headers)
    : downstream_(downstream), id_(factory_context.localInfo().node().id()),
      value_(computeValue(factory_context)),
      skip_external_clusters_(istio_headers.skip_external_clusters()) {}

std::string MXPropagationMethod::computeValue(
    Server::Configuration::ServerFactoryContext& factory_context) const {
  const auto fb = ::Wasm::Common::extractNodeFlatBufferFromStruct(
      factory_context.localInfo().node().metadata());
  google::protobuf::Struct metadata;
  ::Wasm::Common::extractStructFromNodeFlatBuffer(
      *flatbuffers::GetRoot<::Wasm::Common::FlatNode>(fb.data()), &metadata);
  std::string metadata_bytes;
  ::Wasm::Common::serializeToStringDeterministic(metadata, &metadata_bytes);
  return Base64::encode(metadata_bytes.data(), metadata_bytes.size());
}

void MXPropagationMethod::inject(const StreamInfo::StreamInfo& info, Http::HeaderMap& headers,
                                 Context& ctx) const {
  if (skip_external_clusters_) {
    if (skipMXHeaders(info)) {
      return;
    }
  }
  if (!downstream_ || ctx.request_peer_id_received_) {
    headers.setReference(Headers::get().ExchangeMetadataHeaderId, id_);
  }
  if (!downstream_ || ctx.request_peer_received_) {
    headers.setReference(Headers::get().ExchangeMetadataHeader, value_);
  }
}

FilterConfig::FilterConfig(const io::istio::http::peer_metadata::Config& config,
                           Server::Configuration::FactoryContext& factory_context)
    : shared_with_upstream_(config.shared_with_upstream()),
      // 配置downstream discovery
      downstream_discovery_(
          buildDiscoveryMethods(config.downstream_discovery(), true, factory_context)),
      // 构建upstream discovery
      upstream_discovery_(
          buildDiscoveryMethods(config.upstream_discovery(), false, factory_context)),
      // 构建downstream propagation
      downstream_propagation_(
          buildPropagationMethods(config.downstream_propagation(), true, factory_context)),
      // 构建upstream propagation
      upstream_propagation_(
          buildPropagationMethods(config.upstream_propagation(), false, factory_context)) {}

std::vector<DiscoveryMethodPtr> FilterConfig::buildDiscoveryMethods(
    const Protobuf::RepeatedPtrField<io::istio::http::peer_metadata::Config::DiscoveryMethod>&
        config,
    bool downstream, Server::Configuration::FactoryContext& factory_context) const {
  std::vector<DiscoveryMethodPtr> methods;
  methods.reserve(config.size());
  for (const auto& method : config) {
    switch (method.method_specifier_case()) {
    case io::istio::http::peer_metadata::Config::DiscoveryMethod::MethodSpecifierCase::
        kWorkloadDiscovery:
      // method为Discovery
      methods.push_back(
          std::make_unique<XDSMethod>(downstream, factory_context.serverFactoryContext()));
      break;
    case io::istio::http::peer_metadata::Config::DiscoveryMethod::MethodSpecifierCase::
        kIstioHeaders:
      // method为IstioHeaders
      methods.push_back(
          std::make_unique<MXMethod>(downstream, factory_context.serverFactoryContext()));
      break;
    default:
      break;
    }
  }
  return methods;
}

std::vector<PropagationMethodPtr> FilterConfig::buildPropagationMethods(
    const Protobuf::RepeatedPtrField<io::istio::http::peer_metadata::Config::PropagationMethod>&
        config,
    bool downstream, Server::Configuration::FactoryContext& factory_context) const {
  std::vector<PropagationMethodPtr> methods;
  methods.reserve(config.size());
  for (const auto& method : config) {
    switch (method.method_specifier_case()) {
    case io::istio::http::peer_metadata::Config::PropagationMethod::MethodSpecifierCase::
        kIstioHeaders:
      methods.push_back(std::make_unique<MXPropagationMethod>(
          downstream, factory_context.serverFactoryContext(), method.istio_headers()));
      break;
    default:
      break;
    }
  }
  return methods;
}

void FilterConfig::discoverDownstream(StreamInfo::StreamInfo& info, Http::RequestHeaderMap& headers,
                                      Context& ctx) const {
  discover(info, true, headers, ctx);
}

void FilterConfig::discoverUpstream(StreamInfo::StreamInfo& info, Http::ResponseHeaderMap& headers,
                                    Context& ctx) const {
  discover(info, false, headers, ctx);
}

void FilterConfig::discover(StreamInfo::StreamInfo& info, bool downstream, Http::HeaderMap& headers,
                            Context& ctx) const {
  for (const auto& method : downstream ? downstream_discovery_ : upstream_discovery_) {
    // 从discovery获取peer info
    const auto result = method->derivePeerInfo(info, headers, ctx);
    if (result) {
      // 设置filter state
      setFilterState(info, downstream, *result);
      break;
    }
  }
  for (const auto& method : downstream ? downstream_discovery_ : upstream_discovery_) {
    // 移除header
    method->remove(headers);
  }
}

void FilterConfig::injectDownstream(const StreamInfo::StreamInfo& info,
                                    Http::ResponseHeaderMap& headers, Context& ctx) const {
  for (const auto& method : downstream_propagation_) {
    method->inject(info, headers, ctx);
  }
}

void FilterConfig::injectUpstream(const StreamInfo::StreamInfo& info,
                                  Http::RequestHeaderMap& headers, Context& ctx) const {
  for (const auto& method : upstream_propagation_) {
    method->inject(info, headers, ctx);
  }
}

void FilterConfig::setFilterState(StreamInfo::StreamInfo& info, bool downstream,
                                  const std::string& value) const {
  const absl::string_view key = downstream ? WasmDownstreamPeer : WasmUpstreamPeer;
  if (!info.filterState()->hasDataWithName(key)) {
    // filter state中是否有这个name的数据
    auto node_info = std::make_unique<CelStateHashable>(CelPrototypes::get().NodeInfo);
    // 在node info中设置value
    node_info->setValue(value);
    info.filterState()->setData(
        key, std::move(node_info), StreamInfo::FilterState::StateType::Mutable,
        StreamInfo::FilterState::LifeSpan::FilterChain, sharedWithUpstream());
  } else {
    // 有重复的peer metadata，跳过
    ENVOY_LOG(debug, "Duplicate peer metadata, skipping");
  }
  // This is needed because stats filter awaits for the prefix on the wire and checks for the key
  // presence before emitting any telemetry.
  // 这是需要的，因为stats filter期待prefix，在wire，并且检查key presence，在发射任何的telemetry之前
  const absl::string_view id_key = downstream ? WasmDownstreamPeerID : WasmUpstreamPeerID;
  if (!info.filterState()->hasDataWithName(id_key)) {
    auto node_id = std::make_unique<Filters::Common::Expr::CelState>(CelPrototypes::get().NodeId);
    node_id->setValue("unknown");
    // 设置data
    info.filterState()->setData(
        id_key, std::move(node_id), StreamInfo::FilterState::StateType::Mutable,
        StreamInfo::FilterState::LifeSpan::FilterChain, sharedWithUpstream());
  } else {
    ENVOY_LOG(debug, "Duplicate peer id, skipping");
  }
}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  // 发现downstream
  config_->discoverDownstream(decoder_callbacks_->streamInfo(), headers, ctx_);
  // 注入upstream
  config_->injectUpstream(decoder_callbacks_->streamInfo(), headers, ctx_);
  return Http::FilterHeadersStatus::Continue;
}

bool MXPropagationMethod::skipMXHeaders(const StreamInfo::StreamInfo& info) const {
  const auto& cluster_info = info.upstreamClusterInfo();
  if (cluster_info && cluster_info.value()) {
    const auto& cluster_name = cluster_info.value()->name();
    if (cluster_name == "PassthroughCluster") {
      return true;
    }
    const auto& filter_metadata = cluster_info.value()->metadata().filter_metadata();
    const auto& it = filter_metadata.find("istio");
    if (it != filter_metadata.end()) {
      const auto& skip_mx = it->second.fields().find("external");
      if (skip_mx != it->second.fields().end()) {
        return skip_mx->second.bool_value();
      }
    }
  }
  return false;
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  config_->discoverUpstream(decoder_callbacks_->streamInfo(), headers, ctx_);
  config_->injectDownstream(decoder_callbacks_->streamInfo(), headers, ctx_);
  return Http::FilterHeadersStatus::Continue;
}

absl::StatusOr<Http::FilterFactoryCb> FilterConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& config, const std::string&,
    Server::Configuration::FactoryContext& factory_context) {
  // 获取filter config
  auto filter_config = std::make_shared<FilterConfig>(
      dynamic_cast<const io::istio::http::peer_metadata::Config&>(config), factory_context);
  // 返回添加filter的callback
  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) {
    // 构建filter
    auto filter = std::make_shared<Filter>(filter_config);
    // 添加stream filter
    callbacks.addStreamFilter(filter);
  };
}

REGISTER_FACTORY(FilterConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace PeerMetadata
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
