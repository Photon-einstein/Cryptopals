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

private:
  /**
   * Initializes internal state based on the input length
   *
   * @param sizeInputV The size of the original message in bytes
   */
  void initialization(const std::size_t sizeInputV);

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
  // The four working variables (initialized in `initialization`)
  uint32_t _a{}, _b{}, _c{}, _d{};
  /// Message length in bits.
  uint64_t _ml{};
};

} // namespace MyCryptoLibrary

#endif // MD4_HPP
