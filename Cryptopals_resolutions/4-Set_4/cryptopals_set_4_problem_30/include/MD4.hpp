#ifndef SHA1_HPP
#define SHA1_HPP

#include "./../include/MessageDigest.hpp"

// Define MD4_DIGEST_LENGTH if it is not defined elsewhere.
// MD4 produces a 128-bit (20-byte) digest.
#ifndef MD4_DIGEST_LENGTH
#define MD4_DIGEST_LENGTH 16
#endif

namespace MyCryptoLibrary {

class MD4 : public MessageDigest {
public:
  /// Constructor.
  MD4();

  /// Destructor.
  ~MD4();

  /**
   * @brief Computes the MD4 hash value
   *
   * Computes the MD4 hash of the given input vector
   *
   * @param inputV The input data as a vector of unsigned characters
   * @return A vector of unsigned characters containing the computed hash
   */
  virtual std::vector<unsigned char>
  hash(const std::vector<unsigned char> &inputV) override;

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
   * @param messageSize Size of the entire message that was intended to hash
   * from the start
   *
   * @return A vector of bytes containing the computed hash
   */
  std::vector<unsigned char> hash(const std::vector<unsigned char> &inputV,
                                  uint32_t a, uint32_t b, uint32_t c,
                                  uint32_t d, std::size_t messageSize);

private:
  /**
   * Initializes internal state based on the input length
   *
   * @param sizeInputV The size of the original message in bytes
   */
  void initialization(const std::size_t sizeInputV);

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
  void initialization(const std::size_t sizeInputV, uint32_t a, uint32_t b,
                      uint32_t c, uint32_t d);

  /**
   * Preprocesses the input data (padding, appending length) as required by the
   * MD4 algorithm.
   *
   * @param inputV The input data as a vector of unsigned char.
   */
  void preProcessing(const std::vector<unsigned char> &inputV);

  /// Processes the padded message in 512-bit blocks.
  void processing();

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
  uint32_t operationRounds(uint32_t r1, uint32_t r2, uint32_t r3, uint32_t r4,
                           const std::vector<uint32_t> &x,
                           std::size_t blockIndex, std::size_t leftShiftAmount,
                           std::size_t roundNumber);

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
  static uint32_t f(uint32_t x, uint32_t y, uint32_t z);

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
  static uint32_t g(uint32_t x, uint32_t y, uint32_t z);

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
  static uint32_t h(uint32_t x, uint32_t y, uint32_t z);

  /**
   * Performs a left-rotation (circular shift) on a 32-bit integer.
   *
   * @param value The value to rotate.
   * @param bits The number of bits to rotate by.
   * @return The rotated value.
   */
  static uint32_t leftRotate(uint32_t value, int bits);

  /// Expected output hash size in bytes.
  std::size_t _sizeOutputHash{};
  /// Padded input vector.
  std::vector<unsigned char> _inputVpadded{};
  // The four working variables (initialized in `initialization`)
  uint32_t _a{}, _b{}, _c{}, _d{};
  uint32_t _roundTwoConstant{0x5A827999};
  uint32_t _roundThreeConstant{0x6ED9EBA1};
  /// Message length in bits.
  uint64_t _ml{};
};

} // namespace MyCryptoLibrary

#endif // MD4_HPP
