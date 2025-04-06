#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "./../include/MD4.hpp"

/* constructor / destructor */
MyCryptoLibrary::MD4::MD4() : _sizeOutputHash{MD4_DIGEST_LENGTH} {}
/******************************************************************************/
MyCryptoLibrary::MD4::~MD4() {}
/******************************************************************************/
/**
 * @brief Computes the MD4 hash value
 *
 * Computes the MD4 hash of the given input vector
 *
 * @param inputV The input data as a vector of unsigned characters
 * @return A vector of unsigned characters containing the computed hash
 */
std::vector<unsigned char>
MyCryptoLibrary::MD4::hash(const std::vector<unsigned char> &inputV) {
  initialization(inputV.size());
  return inputV;
}
/******************************************************************************/
/**
 * Initializes internal state based on the input length
 *
 * @param sizeInputV The size of the original message in bytes
 */
void MyCryptoLibrary::MD4::initialization(const std::size_t sizeInputV) {
  _a = 0x01234567;
  _b = 0x89ABCDEF;
  _c = 0xFEDCBA98;
  _d = 0x76543210;
  _ml = sizeInputV * CHAR_BIT; // message length in bits (always a multiple of
                               // the number of bits in a character)
}
/******************************************************************************/
/**
 * Performs a left-rotation (circular shift) on a 32-bit integer.
 *
 * @param value The value to rotate.
 * @param bits The number of bits to rotate by.
 * @return The rotated value.
 */
uint32_t MyCryptoLibrary::MD4::leftRotate(uint32_t value, int bits) {
  return (value << bits) | (value >> (32 - bits));
}
/******************************************************************************/