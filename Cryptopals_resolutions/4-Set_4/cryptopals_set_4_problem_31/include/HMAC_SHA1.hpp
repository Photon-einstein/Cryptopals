#ifndef HMAC_SHA1_H
#define HMAC_SHA1_H

#include "./../include/HMAC.hpp"
#include "./../include/SHA1.hpp"

#include <memory>
#include <vector>

namespace MyCryptoLibrary {

class HMAC_SHA1 : public HMAC {
public:
  /* constructor / destructor*/
  HMAC_SHA1();
  virtual ~HMAC_SHA1();

  /* public methods */
  /**
   * @brief Calculates a given hmac-sha1(k, m)
   *
   * This method calculates a given hmac(k, m)
   *
   * @param key The key to be used in the hmac-sha1
   * @param msg The message to be used in the hmac-sha1
   *
   * @return The hmac-sha1(k, m) in a vector format
   */
  virtual std::vector<unsigned char>
  hmac(const std::vector<unsigned char> &key,
       const std::vector<unsigned char> &message) override;

private:
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
                       const std::size_t blockSize) override;

  std::shared_ptr<MyCryptoLibrary::SHA1> _sha1;
  const std::size_t _blockSize{64}; // bytes
  std::vector<unsigned char> _opadV, _ipadV, _keyBlock;
};

} // namespace MyCryptoLibrary

#endif // HMAC_SHA1_HPP
