#include "kmesh_tlv.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

Network::FilterStatus KmeshTlvFilter::onAccept(Network::ListenerFilterCallbacks&) {
  ENVOY_LOG(trace, "original_dst: new connection accepted");

  return Network::FilterStatus::Continue;
}

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy