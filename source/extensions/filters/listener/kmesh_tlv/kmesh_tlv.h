#pragma once

#include "envoy/network/filter.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

enum class ReadOrParseState { Done, TryAgainLater, Error, SkipFilter };

constexpr uint8_t TLV_TYPE_LEN = 0x1;
constexpr uint8_t TLV_LENGTH_LEN = 0x4;
constexpr uint8_t TLV_TYPE_SERVICE = 0x1;
constexpr uint8_t TLV_TYPE_ENDING = 0xfe;
constexpr uint8_t TLV_TYPE_EXTENSION = 0xff;

enum TlvParseState { TypeAndLength = 0, Content = 1 };

/**
 * Implementation of a kmesh tlv listener filter.
 */
class KmeshTlvFilter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

  size_t maxReadBytes() const override { return max_kmesh_tlv_len_; }

  Network::FilterStatus onData(Network::ListenerFilterBuffer&) override;

private:
  ReadOrParseState parseBuffer(Network::ListenerFilterBuffer& buffer);
  // TODO: set max length properly.
  static const size_t MAX_KMESH_TLV_LEN = 256;

  Network::ListenerFilterCallbacks* cb_{};

  TlvParseState state_{TypeAndLength};

  uint32_t expected_length_{TLV_TYPE_LEN + TLV_LENGTH_LEN};

  uint32_t index_{0};

  uint32_t content_length_{0};

  uint32_t max_kmesh_tlv_len_{MAX_KMESH_TLV_LEN};
};

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
