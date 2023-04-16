#include <stdexcept>

#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"

/* constructor / destructor */
PadPKCS_7::PadPKCS_7(int blockSize) : Pad::Pad(blockSize) {

}
/******************************************************************************/
PadPKCS_7::~PadPKCS_7() {

}
/******************************************************************************/
/* this function makes the padding using PKCS#7 format, in the end it will return
the padding result by reference in the v vector and by value true if all ok or
false otherwise */
bool PadPKCS_7::pad(std::vector<unsigned char> &v) {
  if (_blockSize <= 0 && _blockSize > 255) {
    return false;
  }
  int i, padSize = _blockSize - (v.size()%_blockSize);
  unsigned char c = (unsigned char)padSize;
  for (i = 0; i < padSize; ++i) {
    v.emplace_back(c);
  }
  return true;
}
/******************************************************************************/
/* this function makes the unpadding using PKCS#7 format, in the end it will return
the unpadding result by reference in the v vector and by value true if all ok or
false otherwise */
bool PadPKCS_7::unpad(std::vector<unsigned char> &v) {
  if (v.size() % _blockSize != 0 || v[v.size()-1] > _blockSize) {
    return false;
  }
  int i, size = v.size();
  unsigned char lastPadValue = v[v.size()-1];
  /* validate pad value */
  for (i = size-1; i > size-lastPadValue-1; --i) {
    if (v[i] != lastPadValue) {
      return false;
    }
  }
  v.erase(v.begin()+size-lastPadValue, v.begin()+size);
  return true;
}
/******************************************************************************/
/* this function does the check of the padding PadPKCS_7, in the end it
returns true if the padding is ok or throws and exception if the padding is
not ok */
bool PadPKCS_7::testPadding(std::vector<unsigned char> &v) {
  if (v.size() % _blockSize != 0) {
    throw std::invalid_argument("Padded vector size must be a multiple of the block size.");
  }
  int size = v.size(), i;
  unsigned char lastC = v[size-1];
  if (lastC > _blockSize) {
    throw std::invalid_argument("Padded size cannot be greater than the block size.");
  }
  for (i = 0; i < lastC; ++i) {
    if (v[size-1-i] != lastC) {
      throw std::domain_error("The padding char should not change during the padding length.");
    }
  }
  /* if it reaches here then the padding was ok */
  return true;
}
/******************************************************************************/
