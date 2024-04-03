#pragma once

#include "envoy/network/filter.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

/**
 * Implementation of a kmesh tlv listener filter.
 */
class KmeshTlvFilter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

  size_t maxReadBytes() const override { return max_kmesh_tlv_len_; }

  Network::FilterStatus onData(Network::ListenerFilterBuffer&) override {
    return Network::FilterStatus::Continue;
  };

private:
  // TODO: set max length properly.
  static const size_t MAX_KMESH_TLV_LEN = 256;

  size_t max_kmesh_tlv_len_{MAX_KMESH_TLV_LEN};
};

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
