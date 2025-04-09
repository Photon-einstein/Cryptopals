#ifndef MD4_INTERNAL_STATE_HPP
#define MD4_INTERNAL_STATE_HPP

#include <cstdint>
#include <vector>

namespace MD4InternalState {
struct MD4InternalState {
  std::vector<uint32_t> _internalState;
};
}; // namespace MD4InternalState

#endif // MD4_INTERNAL_STATE_HPP
