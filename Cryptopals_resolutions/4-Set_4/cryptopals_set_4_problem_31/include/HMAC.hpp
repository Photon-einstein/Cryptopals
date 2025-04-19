#ifndef HMAC_H
#define HMAC_H

#include <vector>

namespace MyCryptoLibrary {

class HMAC {
public:
  /* constructor / destructor*/
  HMAC();
  virtual ~HMAC();

  /* public methods */
  /**
   * @brief Calculates a given hmac(k, m)
   *
   * This virtual method calculates a given hmac of a plaintext in inputV
   *
   * @param key The key to be used in the hmac
   * @param msg The message to be used in the hmac
   *
   * @return The hmac(k, m) in a vector format
   */
  virtual std::vector<unsigned char>
  hmac(const std::vector<unsigned char> &key,
       const std::vector<unsigned char> &message) = 0;

protected:
  /* private methods */
  /**
   * @brief Calculates a block sized key
   *
   * This virtual method calculates a given block sized key
   *
   * @param key The key to be used in the hmac
   * @param blockSize The size of a block
   *
   * @return The key with a correct block size
   */
  virtual std::vector<unsigned char>
  computeBlockSizedKey(const std::vector<unsigned char> &key,
                       const std::size_t blockSize) = 0;

  const unsigned char _opad{0x5C};
  const unsigned char _ipad{0x36};
};

} // namespace MyCryptoLibrary

#endif // HMAC_HPP
