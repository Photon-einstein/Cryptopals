#include <stdexcept>

#include "./../include/Pad.h"

/* constructor / destructor */
Pad::Pad(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("blockSize argument must be positive");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
Pad::~Pad() {
}
/******************************************************************************/
