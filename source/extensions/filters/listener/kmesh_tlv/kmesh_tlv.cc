#include "kmesh_tlv.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"
#include "source/common/network/filter_state_dst_address.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

Network::FilterStatus KmeshTlvFilter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "kmesh_tlv: new connection accepted");
  cb_ = &cb;
  // Waiting for data.
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus KmeshTlvFilter::onData(Network::ListenerFilterBuffer& buffer) {
  const ReadOrParseState read_state = parseBuffer(buffer);
  switch (read_state) {
  case ReadOrParseState::Error:
    cb_->socket().ioHandle().close();
    return Network::FilterStatus::StopIteration;
  case ReadOrParseState::TryAgainLater:
    return Network::FilterStatus::StopIteration;
  case ReadOrParseState::SkipFilter:
    return Network::FilterStatus::Continue;
  case ReadOrParseState::Done:
    return Network::FilterStatus::Continue;
  }
  return Network::FilterStatus::Continue;
}

ReadOrParseState KmeshTlvFilter::parseBuffer(Network::ListenerFilterBuffer& buffer) {
  ENVOY_LOG(info, "--- into proxy protocol listener filter abc");
  auto raw_slice = buffer.rawSlice();
  const uint8_t* buf = static_cast<const uint8_t*>(raw_slice.mem_);

  while (raw_slice.len_ >= expected_length_) {
    ENVOY_LOG(info, "--- raw_slice.len is {}, expected length is {}", raw_slice.len_,
              expected_length_);
    switch (state_) {
    case TlvParseState::TypeAndLength:
      ENVOY_LOG(info, "-- state is TypeAndLength");
      ENVOY_LOG(info, "-- index_ is {}, buf[index_] is {}", index_, buf[index_]);
      if (buf[index_] == TLV_TYPE_SERVICE) {
        ENVOY_LOG(info, "--- GET TLV TYPE SERVICE");
        uint32_t content_len = 0;
        std::memcpy(&content_len, buf + index_ + 1, TLV_TYPE_LEN);
        ENVOY_LOG(info, "--- GET TLV LENGTH IS {}", content_len);
        expected_length_ += content_len;
        content_length_ = content_len;
        index_ += TLV_TYPE_LEN + TLV_LENGTH_LEN;
        state_ = TlvParseState::Content;

      } else if (buf[index_] == TLV_TYPE_ENDING) {
        ENVOY_LOG(info, "--- GET TLV TYPE ENDING");
        buffer.drain(expected_length_);

        return ReadOrParseState::Done;
      }
      break;

    case TlvParseState::Content:
      ENVOY_LOG(info, "-- state is Content");

      sockaddr_storage addr;
      int len;

      addr.ss_family = AF_INET;
      len = sizeof(struct sockaddr_in);
      ENVOY_LOG(info, "-- len is {}", len);
      auto in4 = reinterpret_cast<struct sockaddr_in*>(&addr);
      std::memcpy(&in4->sin_addr, buf + index_ + 1, len);
      std::memcpy(&in4->sin_port, buf + index_ + 1 + len, 2);

      std::string addrString =
          (*Envoy::Network::Address::addressFromSockAddr(addr, len, false))->asString();
      // std::string addr(reinterpret_cast<const char*>(buf + index_), content_length_);

      ENVOY_LOG(info, "-- addresss is {}", addrString);
      const auto address = Network::Utility::parseInternetAddressAndPort(addrString);
      cb_->filterState().setData(
          "envoy.filters.listener.original_dst.local_ip",
          std::make_shared<Network::AddressObject>(address),
          StreamInfo::FilterState::StateType::Mutable,
          StreamInfo::FilterState::LifeSpan::Connection,
          StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
      expected_length_ += (TLV_TYPE_LEN + TLV_LENGTH_LEN);
      index_ += content_length_;
      state_ = TlvParseState::TypeAndLength;
    }
  }

  return ReadOrParseState::TryAgainLater;
}

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy