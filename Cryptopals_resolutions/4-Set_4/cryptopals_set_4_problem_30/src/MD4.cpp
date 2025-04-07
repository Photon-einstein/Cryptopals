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
/// Processes the padded message in 512-bit blocks.
void MyCryptoLibrary::MD4::processing() {
  // Process the padded input in 512-bit blocks / 16 word blocks / 64 bytes
  uint32_t aa, bb, cc, dd;
  std::size_t blockIndex, leftShiftAmount;
  for (std::size_t i = 0; i < _inputVpadded.size(); i += 64) {
    std::vector<unsigned char> x(_inputVpadded.begin() + i,
                                 _inputVpadded.begin() + i + 64);
    // Save register values
    aa = _a;
    bb = _b;
    cc = _c;
    dd = _d;
    // Round 1
    blockIndex = -1;
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      leftShiftAmount = 3;
      _a = operationRoundOne(_a, _b, _c, _d, x, ++blockIndex, leftShiftAmount);
      leftShiftAmount = 7;
      _d = operationRoundOne(_d, _a, _b, _c, x, ++blockIndex, leftShiftAmount);
      leftShiftAmount = 11;
      _c = operationRoundOne(_c, _d, _a, _b, x, ++blockIndex, leftShiftAmount);
      leftShiftAmount = 19;
      _b = operationRoundOne(_b, _c, _d, _a, x, ++blockIndex, leftShiftAmount);
    }
    // Round 2
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      blockIndex = roundOperations;
      leftShiftAmount = 3;
      _a = operationRoundTwo(_a, _b, _c, _d, x, blockIndex, leftShiftAmount);
      blockIndex += 4;
      leftShiftAmount = 5;
      _d = operationRoundTwo(_d, _a, _b, _c, x, blockIndex, leftShiftAmount);
      blockIndex += 4;
      leftShiftAmount = 9;
      _c = operationRoundTwo(_c, _d, _a, _b, x, blockIndex, leftShiftAmount);
      blockIndex += 4;
      leftShiftAmount = 13;
      _b = operationRoundTwo(_b, _c, _d, _a, x, blockIndex, leftShiftAmount);
    }
    // Round 3
    std::vector<std::size_t> blockRoundInitializer{0, 2, 1, 3};
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      blockIndex = blockRoundInitializer[roundOperations];
      leftShiftAmount = 3;
      _a = operationRoundThree(_a, _b, _c, _d, x, blockIndex, leftShiftAmount);
      blockIndex += 8;
      leftShiftAmount = 9;
      _d = operationRoundThree(_d, _a, _b, _c, x, blockIndex, leftShiftAmount);
      blockIndex -= 4;
      leftShiftAmount = 11;
      _c = operationRoundThree(_c, _d, _a, _b, x, blockIndex, leftShiftAmount);
      blockIndex += 8;
      leftShiftAmount = 15;
      _b = operationRoundThree(_b, _c, _d, _a, x, blockIndex, leftShiftAmount);
    }
    // Update the registers at the end of each block
    _a += aa;
    _b += bb;
    _c += cc;
    _d += dd;
  }
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message, at round 1
 *
 * @brief Computes: res = (r1 + f(r2, r3, r4) + x[blockIndex]) <<<
 * leftShiftAmount
 *
 * @param r1 The first 32 bit argument
 * @param r2 The second 32 bit argument
 * @param r3 The third 32 bit argument
 * @param x  The block currently in process
 * @param blockIndex The index of the block
 * @param leftShiftAmount The amount to be left circularly shifted
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::operationRoundOne(
    uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4,
    const std::vector<unsigned char> &x, std::size_t blockIndex,
    std::size_t leftShiftAmount) {
  return leftRotate(r1 + f(r2, r3, r4) + x[blockIndex], leftShiftAmount);
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message, at round 2
 *
 * @brief Computes: res = (r1 + g(r2, r3, r4) + x[blockIndex] +
 * _roundTwoConstant) <<< leftShiftAmount
 *
 * @param r1 The first 32 bit argument
 * @param r2 The second 32 bit argument
 * @param r3 The third 32 bit argument
 * @param x  The block currently in process
 * @param blockIndex The index of the block
 * @param leftShiftAmount The amount to be left circularly shifted
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::operationRoundTwo(
    uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4,
    const std::vector<unsigned char> &x, std::size_t blockIndex,
    std::size_t leftShiftAmount) {
  return leftRotate(r1 + g(r2, r3, r4) + x[blockIndex] + _roundTwoConstant,
                    leftShiftAmount);
}
/******************************************************************************/
/**
 * Auxiliary function in the processing of the message, at round 3
 *
 * @brief Computes: res = (r1 + h(r2, r3, r4) + x[blockIndex] +
 * _roundThreeConstant) <<< leftShiftAmount
 *
 * @param r1 The first 32 bit argument
 * @param r2 The second 32 bit argument
 * @param r3 The third 32 bit argument
 * @param x  The block currently in process
 * @param blockIndex The index of the block
 * @param leftShiftAmount The amount to be left circularly shifted
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::operationRoundThree(
    uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4,
    const std::vector<unsigned char> &x, std::size_t blockIndex,
    std::size_t leftShiftAmount) {
  return leftRotate(r1 + h(r2, r3, r4) + x[blockIndex] + _roundThreeConstant,
                    leftShiftAmount);
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