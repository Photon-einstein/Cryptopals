#ifndef SHA1_INTERNAL_STATE_HPP
#define SHA1_INTERNAL_STATE_HPP

#include <cstdint>
#include <vector>

namespace SHA1InternalState {
struct SHA1InternalState {
  std::vector<uint32_t> _internalState;
};
}; // namespace SHA1InternalState

#endif // SHA1_INTERNAL_STATE_HPP
