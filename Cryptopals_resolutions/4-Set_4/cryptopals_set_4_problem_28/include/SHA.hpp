#ifndef SHA_H
#define SHA_H

#include <vector>

namespace MyCryptoLibrary {

class SHA {
public:
  /* constructor / destructor*/
  SHA();
  virtual ~SHA();

  /* public methods */
  /**
   * @brief Calculates a given hash
   *
   * This virtual method calculates a given hash of a plaintext in inputV
   *
   * @return The hash of inputV in a vector format
   */
  virtual std::vector<unsigned char>
  hash(const std::vector<unsigned char> &inputV) = 0;

  /// Returns the hash output size in bytes.
  virtual std::size_t getHashOutputSize() = 0;
};

} // namespace MyCryptoLibrary

#endif // SHA_HPP
