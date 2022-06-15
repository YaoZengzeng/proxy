/* Copyright 2019 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/envoy/tcp/metadata_exchange/metadata_exchange.h"

#include <cstdint>
#include <string>

#include "absl/base/internal/endian.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "envoy/network/connection.h"
#include "envoy/stats/scope.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/protobuf/utility.h"
#include "src/envoy/tcp/metadata_exchange/metadata_exchange_initial_header.h"

namespace Envoy {
namespace Tcp {
namespace MetadataExchange {
namespace {

// 构建ProxyHeader
std::unique_ptr<::Envoy::Buffer::OwnedImpl> constructProxyHeaderData(
    const Envoy::ProtobufWkt::Any& proxy_data) {
  // 构建initial_header
  MetadataExchangeInitialHeader initial_header;
  // 对proxy data进行序列化
  std::string proxy_data_str = proxy_data.SerializeAsString();
  // Converting from host to network byte order so that most significant byte is
  // placed first.
  // 将host转换为network byte order，这样首先放置most significant byte
  initial_header.magic =
      absl::ghtonl(MetadataExchangeInitialHeader::magic_number);
  initial_header.data_size = absl::ghtonl(proxy_data_str.length());

  ::Envoy::Buffer::OwnedImpl initial_header_buffer{
      absl::string_view(reinterpret_cast<const char*>(&initial_header),
                        sizeof(MetadataExchangeInitialHeader))};
  auto proxy_data_buffer =
      std::make_unique<::Envoy::Buffer::OwnedImpl>(proxy_data_str);
  proxy_data_buffer->prepend(initial_header_buffer);
  return proxy_data_buffer;
}

bool serializeToStringDeterministic(const google::protobuf::Struct& metadata,
                                    std::string* metadata_bytes) {
  google::protobuf::io::StringOutputStream md(metadata_bytes);
  google::protobuf::io::CodedOutputStream mcs(&md);

  mcs.SetSerializationDeterministic(true);
  if (!metadata.SerializeToCodedStream(&mcs)) {
    return false;
  }
  return true;
}

}  // namespace

MetadataExchangeConfig::MetadataExchangeConfig(
    const std::string& stat_prefix, const std::string& protocol,
    const FilterDirection filter_direction, Stats::Scope& scope)
    : scope_(scope),
      stat_prefix_(stat_prefix),
      protocol_(protocol),
      filter_direction_(filter_direction),
      stats_(generateStats(stat_prefix, scope)) {}

Network::FilterStatus MetadataExchangeFilter::onData(Buffer::Instance& data,
                                                     bool) {
  switch (conn_state_) {
    case Invalid:
      FALLTHRU;
    case Done:
      // No work needed if connection state is Done or Invalid.
      // 当状态为Done或者Invalid时，不需要再做任何事
      return Network::FilterStatus::Continue;
    case ConnProtocolNotRead: {
      // If Alpn protocol is not the expected one, then return.
      // Else find and write node metadata.
      // 如果Alpn protocol不是预期的，之后返回，否则找到并且写入node metadata
      if (read_callbacks_->connection().nextProtocol() != config_->protocol_) {
        ENVOY_LOG(trace, "Alpn Protocol Not Found. Expected {}, Got {}",
                  config_->protocol_,
                  read_callbacks_->connection().nextProtocol());
        setMetadataNotFoundFilterState();
        conn_state_ = Invalid;
        config_->stats().alpn_protocol_not_found_.inc();
        return Network::FilterStatus::Continue;
      }
      conn_state_ = WriteMetadata;
      config_->stats().alpn_protocol_found_.inc();
      FALLTHRU;
    }
    case WriteMetadata: {
      // TODO(gargnupur): Try to move this just after alpn protocol is
      // determined and first onData is called in Downstream filter.
      // If downstream filter, write metadata.
      // Otherwise, go ahead and try to read initial header and proxy data.
      writeNodeMetadata();
      FALLTHRU;
    }
    case ReadingInitialHeader:
    case NeedMoreDataInitialHeader: {
      // 试着读取初始的Proxy Header
      tryReadInitialProxyHeader(data);
      if (conn_state_ == NeedMoreDataInitialHeader) {
        return Network::FilterStatus::StopIteration;
      }
      if (conn_state_ == Invalid) {
        return Network::FilterStatus::Continue;
      }
      FALLTHRU;
    }
    case ReadingProxyHeader:
    case NeedMoreDataProxyHeader: {
      // 试着读取Proxy Data
      tryReadProxyData(data);
      if (conn_state_ == NeedMoreDataProxyHeader) {
        return Network::FilterStatus::StopIteration;
      }
      if (conn_state_ == Invalid) {
        return Network::FilterStatus::Continue;
      }
      FALLTHRU;
    }
    default:
      conn_state_ = Done;
      return Network::FilterStatus::Continue;
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus MetadataExchangeFilter::onNewConnection() {
  return Network::FilterStatus::Continue;
}

Network::FilterStatus MetadataExchangeFilter::onWrite(Buffer::Instance&, bool) {
  switch (conn_state_) {
    case Invalid:
    case Done:
      // No work needed if connection state is Done or Invalid.
      // 当连接状态为Done或者为Invalid时，则不需要再处理
      return Network::FilterStatus::Continue;
    case ConnProtocolNotRead: {
      if (read_callbacks_->connection().nextProtocol() != config_->protocol_) {
        ENVOY_LOG(trace, "Alpn Protocol Not Found. Expected {}, Got {}",
                  config_->protocol_,
                  read_callbacks_->connection().nextProtocol());
        setMetadataNotFoundFilterState();
        conn_state_ = Invalid;
        config_->stats().alpn_protocol_not_found_.inc();
        return Network::FilterStatus::Continue;
      } else {
        // application protocol匹配，状态改为WriteMetadata
        conn_state_ = WriteMetadata;
        config_->stats().alpn_protocol_found_.inc();
      }
      FALLTHRU;
    }
    case WriteMetadata: {
      // TODO(gargnupur): Try to move this just after alpn protocol is
      // determined and first onWrite is called in Upstream filter.
      writeNodeMetadata();
      FALLTHRU;
    }
    // 对于onWrite，ReadingInitialHeader, ReadingProxyHeader，NeedMoreDataInitialHeader
    // 以及NeedMoreDataProxyHeader都不处理
    case ReadingInitialHeader:
    case ReadingProxyHeader:
    case NeedMoreDataInitialHeader:
    case NeedMoreDataProxyHeader:
      // These are to be handled in Reading Pipeline.
      // 上面这些都是在Reading Pipeline中被处理
      return Network::FilterStatus::Continue;
  }

  return Network::FilterStatus::Continue;
}

void MetadataExchangeFilter::writeNodeMetadata() {
  if (conn_state_ != WriteMetadata) {
    return;
  }

  Envoy::ProtobufWkt::Struct data;
  Envoy::ProtobufWkt::Struct* metadata =
      (*data.mutable_fields())[ExchangeMetadataHeader].mutable_struct_value();
  // 获取metadata
  getMetadata(metadata);
  std::string metadata_id = getMetadataId();
  if (!metadata_id.empty()) {
    (*data.mutable_fields())[ExchangeMetadataHeaderId].set_string_value(
        metadata_id);
  }
  if (data.fields_size() > 0) {
    Envoy::ProtobufWkt::Any metadata_any_value;
    *metadata_any_value.mutable_type_url() = StructTypeUrl;
    std::string serialized_data;
    serializeToStringDeterministic(data, &serialized_data);
    *metadata_any_value.mutable_value() = serialized_data;
    // 将metadata写入buffer，调用constructProxyHeaderData构建
    // 一个header，直接发送到upstream connection中
    std::unique_ptr<::Envoy::Buffer::OwnedImpl> buf =
        constructProxyHeaderData(metadata_any_value);
    // 将WriteData写入Filter Chain
    write_callbacks_->injectWriteDataToFilterChain(*buf, false);
    config_->stats().metadata_added_.inc();
  }

  // 将状态改为ReadingInitialHeader，写入本地的metadata之后，就等着对端的
  // InitialHeader
  conn_state_ = ReadingInitialHeader;
}

void MetadataExchangeFilter::tryReadInitialProxyHeader(Buffer::Instance& data) {
  if (conn_state_ != ReadingInitialHeader &&
      conn_state_ != NeedMoreDataInitialHeader) {
    return;
  }
  const uint32_t initial_header_length = sizeof(MetadataExchangeInitialHeader);
  if (data.length() < initial_header_length) {
    config_->stats().initial_header_not_found_.inc();
    // Not enough data to read. Wait for it to come.
    // 没有足够的数据读取，等待
    ENVOY_LOG(debug,
              "Alpn Protocol matched. Waiting to read more initial header.");
    conn_state_ = NeedMoreDataInitialHeader;
    return;
  }
  MetadataExchangeInitialHeader initial_header;
  // 把数据拷贝到initial_header中
  data.copyOut(0, initial_header_length, &initial_header);
  // initial header里包含了一个magic和一个长度值
  if (absl::gntohl(initial_header.magic) !=
      MetadataExchangeInitialHeader::magic_number) {
    config_->stats().initial_header_not_found_.inc();
    setMetadataNotFoundFilterState();
    ENVOY_LOG(warn,
              "Incorrect istio-peer-exchange ALPN magic. Peer missing TCP "
              // 对端缺失MetadataExchange filter
              "MetadataExchange filter.");
    conn_state_ = Invalid;
    return;
  }
  proxy_data_length_ = absl::gntohl(initial_header.data_size);
  // Drain the initial header length bytes read.
  // 抽取出读到的initial header长度的字节
  data.drain(initial_header_length);
  conn_state_ = ReadingProxyHeader;
}

void MetadataExchangeFilter::tryReadProxyData(Buffer::Instance& data) {
  if (conn_state_ != ReadingProxyHeader &&
      conn_state_ != NeedMoreDataProxyHeader) {
    return;
  }
  if (data.length() < proxy_data_length_) {
    // Not enough data to read. Wait for it to come.
    // 没有读到足够的数据，等待它的到来
    ENVOY_LOG(debug, "Alpn Protocol matched. Waiting to read more metadata.");
    conn_state_ = NeedMoreDataProxyHeader;
    return;
  }
  std::string proxy_data_buf =
      std::string(static_cast<const char*>(data.linearize(proxy_data_length_)),
                  proxy_data_length_);
  Envoy::ProtobufWkt::Any proxy_data;
  if (!proxy_data.ParseFromString(proxy_data_buf)) {
    config_->stats().header_not_found_.inc();
    setMetadataNotFoundFilterState();
    ENVOY_LOG(warn,
              "Alpn protocol matched. Magic matched. Metadata Not found.");
    conn_state_ = Invalid;
    return;
  }
  data.drain(proxy_data_length_);

  // Set Metadata
  // 设置Metadata
  Envoy::ProtobufWkt::Struct value_struct =
      Envoy::MessageUtil::anyConvert<Envoy::ProtobufWkt::Struct>(proxy_data);
  // 找到ExchangeMetadataHeader
  auto key_metadata_it = value_struct.fields().find(ExchangeMetadataHeader);
  if (key_metadata_it != value_struct.fields().end()) {
    // 更新Peer
    updatePeer(key_metadata_it->second.struct_value());
  }
  // 找到metadata id
  const auto key_metadata_id_it =
      value_struct.fields().find(ExchangeMetadataHeaderId);
  if (key_metadata_id_it != value_struct.fields().end()) {
    Envoy::ProtobufWkt::Value val = key_metadata_id_it->second;
    // 更新Peer Id
    updatePeerId(toAbslStringView(config_->filter_direction_ ==
                                          FilterDirection::Downstream
                                      ? ::Wasm::Common::kDownstreamMetadataIdKey
                                      : ::Wasm::Common::kUpstreamMetadataIdKey),
                 val.string_value());
  }
}

void MetadataExchangeFilter::updatePeer(
    const Envoy::ProtobufWkt::Struct& struct_value) {
  const auto fb = ::Wasm::Common::extractNodeFlatBufferFromStruct(struct_value);

  // Filter object captures schema by view, hence the global singleton for the
  // prototype.
  auto state =
      std::make_unique<::Envoy::Extensions::Filters::Common::Expr::CelState>(
          MetadataExchangeConfig::nodeInfoPrototype());
  state->setValue(
      absl::string_view(reinterpret_cast<const char*>(fb.data()), fb.size()));

  // 设置metadata key
  auto key = config_->filter_direction_ == FilterDirection::Downstream
                 ? ::Wasm::Common::kDownstreamMetadataKey
                 : ::Wasm::Common::kUpstreamMetadataKey;
  read_callbacks_->connection().streamInfo().filterState()->setData(
      absl::StrCat("wasm.", toAbslStringView(key)), std::move(state),
      StreamInfo::FilterState::StateType::Mutable,
      StreamInfo::FilterState::LifeSpan::Connection);
}

void MetadataExchangeFilter::updatePeerId(absl::string_view key,
                                          absl::string_view value) {
  CelStatePrototype prototype(
      /* read_only = */ false,
      ::Envoy::Extensions::Filters::Common::Expr::CelStateType::String,
      absl::string_view(), StreamInfo::FilterState::LifeSpan::Connection);
  auto state =
      std::make_unique<::Envoy::Extensions::Filters::Common::Expr::CelState>(
          prototype);
  state->setValue(value);
  // 设置metadata id
  read_callbacks_->connection().streamInfo().filterState()->setData(
      absl::StrCat("wasm.", key), std::move(state),
      StreamInfo::FilterState::StateType::Mutable, prototype.life_span_);
}

void MetadataExchangeFilter::getMetadata(google::protobuf::Struct* metadata) {
  if (local_info_.node().has_metadata()) {
    // 从Node Flat Buffer中抽取出metadata
    const auto fb = ::Wasm::Common::extractNodeFlatBufferFromStruct(
        local_info_.node().metadata());
    ::Wasm::Common::extractStructFromNodeFlatBuffer(
        *flatbuffers::GetRoot<::Wasm::Common::FlatNode>(fb.data()), metadata);
  }
}

std::string MetadataExchangeFilter::getMetadataId() {
  return local_info_.node().id();
}

void MetadataExchangeFilter::setMetadataNotFoundFilterState() {
  auto key = config_->filter_direction_ == FilterDirection::Downstream
                 ? ::Wasm::Common::kDownstreamMetadataIdKey
                 : ::Wasm::Common::kUpstreamMetadataIdKey;
  updatePeerId(toAbslStringView(key), ::Wasm::Common::kMetadataNotFoundValue);
}

}  // namespace MetadataExchange
}  // namespace Tcp
}  // namespace Envoy
