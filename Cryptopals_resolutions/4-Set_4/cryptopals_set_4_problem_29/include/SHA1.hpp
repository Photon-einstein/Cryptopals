#ifndef SHA1_HPP
#define SHA1_HPP

#include "./../include/SHA.hpp"

// Define SHA_DIGEST_LENGTH if it is not defined elsewhere.
// SHA-1 produces a 160-bit (20-byte) digest.
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

namespace MyCryptoLibrary {

class SHA1 : public SHA {
public:
  /// Constructor.
  SHA1();

  /// Destructor.
  ~SHA1();

  /**
   * @brief Computes the SHA-1 hash value
   *
   * Computes the SHA-1 hash of the given input vector
   *
   * @param inputV The input data as a vector of unsigned characters
   * @return A vector of unsigned characters containing the computed hash
   */
  virtual std::vector<unsigned char>
  hash(const std::vector<unsigned char> &inputV) override;

  /**
   * @brief Computes the SHA-1 hash value
   *
   * Computes the SHA-1 hash of the given input vector from a predefined
   * internal state
   *
   * @param inputV The input data as a vector of unsigned characters
   * @param h0 Internal state of the SHA1
   * @param h1 Internal state of the SHA1
   * @param h2 Internal state of the SHA1
   * @param h3 Internal state of the SHA1
   * @param h4 Internal state of the SHA1
   * @param messageSize Size of the entire message that was intended to hash
   * from the start
   *
   * @return A vector of bytes containing the computed hash
   */
  std::vector<unsigned char> hash(const std::vector<unsigned char> &inputV,
                                  uint32_t h0, uint32_t h1, uint32_t h2,
                                  uint32_t h3, uint32_t h4,
                                  std::size_t messageSize);

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
   * @param h0 Internal state of the SHA1
   * @param h1 Internal state of the SHA1
   * @param h2 Internal state of the SHA1
   * @param h3 Internal state of the SHA1
   * @param h4 Internal state of the SHA1
   */
  void initialization(const std::size_t sizeInputV, uint32_t h0, uint32_t h1,
                      uint32_t h2, uint32_t h3, uint32_t h4);

  /**
   * Preprocesses the input data (padding, appending length) as required by the
   * SHA-1 algorithm.
   *
   * @param inputV The input data as a vector of unsigned char.
   */
  void preProcessing(const std::vector<unsigned char> &inputV);

  /// Processes the padded message in 512-bit blocks.
  void processing();

  /**
   * Performs a left-rotation (circular shift) on a 32-bit integer.
   *
   * @param value The value to rotate.
   * @param bits The number of bits to rotate by.
   * @return The rotated value.
   */
  static uint32_t leftRotate(uint32_t value, int bits);

  // Internal state variables

  /// Expected output hash size in bytes.
  std::size_t _sizeOutputHash{};

  /// Padded input vector.
  std::vector<unsigned char> _inputVpadded{};

  // The five working variables (initialized in `initialization`)
  uint32_t _h0{}, _h1{}, _h2{}, _h3{}, _h4{};

  /// Message length in bits.
  uint64_t _ml{};
};

} // namespace MyCryptoLibrary

#endif // SHA1_HPP
