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
 * Preprocesses the input data (padding, appending length) as required by the
 * MD4 algorithm.
 *
 * @param inputV The input data as a vector of unsigned char.
 */
void MyCryptoLibrary::MD4::preProcessing(
    const std::vector<unsigned char> &inputV) {
  // Initialize padded input vector with original message
  _inputVpadded = inputV;

  // Step 1: Append the bit '1' (equivalent to adding 0x80)
  _inputVpadded.push_back(0x80);

  // Step 2: Append '0' bits until the length of the message (in bits) is
  // congruent to 448 mod 512
  while ((_inputVpadded.size() * 8) % 512 != 448) {
    _inputVpadded.push_back(0x00);
  }

  // Step 3: Append the original message length (ml) as a 64-bit little-endian
  // integer _ml is already in bits
  for (int i = 0; i < 8; ++i) {
    _inputVpadded.push_back(
        static_cast<unsigned char>((_ml >> (i * 8)) & 0xFF));
  }
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message
 *
 * @brief Computes: x.y or (not x).z
 *
 * @param x The first 32 bit argument
 * @param y The second 32 bit argument
 * @param z The third 32 bit argument
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::f(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | ((~x) & z);
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message
 *
 * @brief Computes: x.y or x.z or y.z
 *
 * @param x The first 32 bit argument
 * @param y The second 32 bit argument
 * @param z The third 32 bit argument
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::g(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (x & z) | (y & z);
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message
 *
 * @brief Computes: x xor y xor z
 *
 * @param x The first 32 bit argument
 * @param y The second 32 bit argument
 * @param z The third 32 bit argument
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::h(uint32_t x, uint32_t y, uint32_t z) {
  return x ^ y ^ z;
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