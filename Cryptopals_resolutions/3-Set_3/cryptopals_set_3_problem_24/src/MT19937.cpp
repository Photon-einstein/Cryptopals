#include <stdexcept>

#include "./../include/MT19937.h"

/* constructor / destructor */

/* Create a length n array to store the state of the generator */
MT19937::MT19937(unsigned int seed) : _index(_n) {
  _mt[0] = static_cast<std::uint32_t>(seed);
  _lowerMask = (1 << _r) - 1;
  _upperMask = (~_lowerMask) >> (_w - 32);
  MT19937::seedMt(seed);
}
/******************************************************************************/
MT19937::~MT19937() {}
/******************************************************************************/
/* initialize the generator from the seed */
void MT19937::seedMt(unsigned int seed) {
  std::size_t i;
  _index = _n;
  for (i = 1; i < _n; ++i) {
    _mt[i] = _f * (_mt[i - 1] ^ (_mt[i - 1] >> (_w - 2))) + i;
  }
}
/******************************************************************************/
/* Extract a tempered value based on MT[index] calling twist() every n numbers
 */
std::uint32_t MT19937::extractNumber() {
  if (_index >= _n) {
    if (_index > _n) {
      throw std::invalid_argument("Generator was never seeded");
    }
    twist();
  }
  unsigned int y = _mt[_index];
  /* advance index */
  ++_index;
  /* rest of operations */
  y ^= ((y >> _u) & _d);
  y ^= ((y << _s) & _b);
  y ^= ((y << _t) & _c);
  y ^= (y >> _l);
  return y;
}
/******************************************************************************/
/* Generate the next n values from the series x_i */
void MT19937::twist() {
  unsigned int x, xA;
  for (std::size_t i = 0; i < _n; ++i) {
    x = (_mt[i] & _upperMask) | (_mt[(i + 1) % _n] & _lowerMask);
    xA = x >> 1;
    /* lowest bit of x is 1 */
    if (x % 2 != 0) {
      xA ^= _a;
    }
    _mt[i] = _mt[(i + _m) % _n] ^ xA;
  }
  _index = 0;
}
/******************************************************************************/
/* this function will return true if the vector _mt19937StateVector has the
same value as the internal state of MT19937 or false otherwise */
bool MT19937::checkEqualVectorState(
    const std::vector<std::uint32_t> &_mt19937StateVector) {
  if (_mt19937StateVector.size() != _n) {
    return false;
  }
  int i;
  for (i = 0; i < _n; ++i) {
    if (_mt[i] != _mt19937StateVector[i]) {
      std::cout << "(_mt[" << i << "] = " << _mt[i]
                << ") != (_mt19937StateVector[" << i
                << "] = " << _mt19937StateVector[i] << ")" << std::endl;
      return false;
    }
  }
  return true;
}
/******************************************************************************/
