#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <stdexcept>

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
  preProcessing(inputV);
  processing();
  std::vector<unsigned char> hashV;
  hashV.reserve(MD4_DIGEST_LENGTH);

  const uint32_t hashParts[] = {_a, _b, _c, _d};

  for (uint32_t part : hashParts) {
    // extraction of bytes start at the lower order end
    hashV.push_back(part & 0xFF);
    hashV.push_back((part >> 8) & 0xFF);
    hashV.push_back((part >> 16) & 0xFF);
    hashV.push_back((part >> 24) & 0xFF);
  }
  return hashV;
}
/******************************************************************************/
/**
 * @brief Computes the MD4 hash value
 *
 * Computes the MD4 hash of the given input vector from a predefined internal
 * state
 *
 * @param inputV The input data as a vector of unsigned characters
 * @param a Internal state of the MD4
 * @param b Internal state of the MD4
 * @param c Internal state of the MD4
 * @param d Internal state of the MD4
 * @param messageSize Size of the entire message that was intended to hash from
 * the start
 *
 * @return A vector of bytes containing the computed hash
 */
std::vector<unsigned char>
MyCryptoLibrary::MD4::hash(const std::vector<unsigned char> &inputV, uint32_t a,
                           uint32_t b, uint32_t c, uint32_t d,
                           std::size_t messageSize) {
  initialization(messageSize, a, b, c, d);
  preProcessing(inputV);
  processing();
  std::vector<unsigned char> hashV;
  hashV.reserve(MD4_DIGEST_LENGTH);

  const uint32_t hashParts[] = {_a, _b, _c, _d};

  for (uint32_t part : hashParts) {
    // extraction of bytes start at the lower order end
    hashV.push_back(part & 0xFF);
    hashV.push_back((part >> 8) & 0xFF);
    hashV.push_back((part >> 16) & 0xFF);
    hashV.push_back((part >> 24) & 0xFF);
  }
  return hashV;
}
/******************************************************************************/
/**
 * Initializes internal state based on the input length
 *
 * @param sizeInputV The size of the original message in bytes
 */
void MyCryptoLibrary::MD4::initialization(const std::size_t sizeInputV) {
  _a = 0x67452301;
  _b = 0xEFCDAB89;
  _c = 0x98BADCFE;
  _d = 0x10325476;
  _ml = sizeInputV * CHAR_BIT; // message length in bits (always a multiple of
                               // the number of bits in a character)
}
/******************************************************************************/
/**
 * Initializes internal state based on the input length and predefined input
 * state
 *
 * @param sizeInputV The size of the original message in bytes
 * @param a Internal state of the MD4
 * @param b Internal state of the MD4
 * @param c Internal state of the MD4
 * @param d Internal state of the MD4
 */
void MyCryptoLibrary::MD4::initialization(const std::size_t sizeInputV,
                                          uint32_t a, uint32_t b, uint32_t c,
                                          uint32_t d) {
  _a = a;
  _b = b;
  _c = c;
  _d = d;
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
  const std::size_t bytesBlockSize{64}, wordsBlockSize{16};
  std::size_t leftShiftAmount;
  std::vector<std::size_t> blockRoundInitializer{0, 2, 1, 3};
  for (std::size_t i = 0; i < _inputVpadded.size(); i += bytesBlockSize) {
    std::vector<unsigned char> x(_inputVpadded.begin() + i,
                                 _inputVpadded.begin() + i + bytesBlockSize);
    std::vector<uint32_t> X;
    // conversion of 64 bytes into 16 words (32 bits) blocks
    for (std::size_t j = 0; j < wordsBlockSize; ++j) {
      X.push_back(static_cast<uint32_t>(x[j * 4]) |
                  (static_cast<uint32_t>(x[j * 4 + 1]) << 8) |
                  (static_cast<uint32_t>(x[j * 4 + 2]) << 16) |
                  (static_cast<uint32_t>(x[j * 4 + 3]) << 24));
    }
    // Save register values
    std::size_t aa = _a, bb = _b, cc = _c, dd = _d;
    // Round 1
    std::size_t roundNumber = 1, blockIndex = -1;
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      leftShiftAmount = 3;
      _a = operationRounds(_a, _b, _c, _d, X, ++blockIndex, leftShiftAmount,
                           roundNumber);
      leftShiftAmount = 7;
      _d = operationRounds(_d, _a, _b, _c, X, ++blockIndex, leftShiftAmount,
                           roundNumber);
      leftShiftAmount = 11;
      _c = operationRounds(_c, _d, _a, _b, X, ++blockIndex, leftShiftAmount,
                           roundNumber);
      leftShiftAmount = 19;
      _b = operationRounds(_b, _c, _d, _a, X, ++blockIndex, leftShiftAmount,
                           roundNumber);
    }
    // Round 2
    roundNumber = 2;
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      blockIndex = roundOperations;
      leftShiftAmount = 3;
      _a = operationRounds(_a, _b, _c, _d, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex += 4;
      leftShiftAmount = 5;
      _d = operationRounds(_d, _a, _b, _c, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex += 4;
      leftShiftAmount = 9;
      _c = operationRounds(_c, _d, _a, _b, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex += 4;
      leftShiftAmount = 13;
      _b = operationRounds(_b, _c, _d, _a, X, blockIndex, leftShiftAmount,
                           roundNumber);
    }
    // Round 3
    roundNumber = 3;
    for (std::size_t roundOperations = 0; roundOperations < 4;
         ++roundOperations) {
      blockIndex = blockRoundInitializer[roundOperations];
      leftShiftAmount = 3;
      _a = operationRounds(_a, _b, _c, _d, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex += 8;
      leftShiftAmount = 9;
      _d = operationRounds(_d, _a, _b, _c, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex -= 4;
      leftShiftAmount = 11;
      _c = operationRounds(_c, _d, _a, _b, X, blockIndex, leftShiftAmount,
                           roundNumber);
      blockIndex += 8;
      leftShiftAmount = 15;
      _b = operationRounds(_b, _c, _d, _a, X, blockIndex, leftShiftAmount,
                           roundNumber);
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
 * Auxiliary function in the processing of the message, at rounds 1/2/3
 *
 * @brief Computes:
 * Round 1: res = (r1 + g(r2, r3, r4) + x[blockIndex] +
 * roundTwoConstant) <<< leftShiftAmount
 *
 * Round 2: res = (r1 + h(r2, r3, r4) + x[blockIndex] +
 * roundThreeConstant) <<< leftShiftAmount
 *
 * Round 3: res = (r1 + h(r2, r3, r4) + x[blockIndex] +
 * roundThreeConstant) <<< leftShiftAmount
 *
 * @param r1 The first 32 bit argument
 * @param r2 The second 32 bit argument
 * @param r3 The third 32 bit argument
 * @param x  The block currently in process
 * @param blockIndex The index of the block
 * @param roundNumber The round identifier
 * @param leftShiftAmount The amount to be left circularly shifted
 * @return The auxiliary method result
 */
uint32_t MyCryptoLibrary::MD4::operationRounds(uint32_t r1, uint32_t r2,
                                               uint32_t r3, uint32_t r4,
                                               const std::vector<uint32_t> &x,
                                               std::size_t blockIndex,
                                               std::size_t leftShiftAmount,
                                               std::size_t roundNumber) const {
  switch (roundNumber) {
  case 1:
    /* code */
    return leftRotate(r1 + f(r2, r3, r4) + x[blockIndex], leftShiftAmount);
  case 2:
    /* code */
    return leftRotate(r1 + g(r2, r3, r4) + x[blockIndex] + _roundTwoConstant,
                      leftShiftAmount);
  case 3:
    /* code */
    return leftRotate(r1 + h(r2, r3, r4) + x[blockIndex] + _roundThreeConstant,
                      leftShiftAmount);
  default:
    const std::string errorMessage{
        "MD4 log | invalid round number received at method "
        "'MyCryptoLibrary::MD4::operationRounds'"};
    throw std::invalid_argument(errorMessage);
  }
  return 0;
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