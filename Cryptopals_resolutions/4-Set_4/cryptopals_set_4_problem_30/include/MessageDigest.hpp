#ifndef MESSAGE_DIGEST_HPP
#define MESSAGE_DIGEST_HPP

#include <vector>

namespace MyCryptoLibrary {

class MessageDigest {
public:
  /* constructor / destructor*/
  MessageDigest();
  virtual ~MessageDigest();

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
};

} // namespace MyCryptoLibrary

#endif // MESSAGE_DIGEST_HPP
