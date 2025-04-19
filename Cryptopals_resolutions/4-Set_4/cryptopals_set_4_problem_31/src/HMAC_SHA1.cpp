#include "./../include/HMAC_SHA1.hpp"
#include "./../include/SHA1.hpp"

/* constructor / destructor */
MyCryptoLibrary::HMAC_SHA1::HMAC_SHA1()
    : _sha1(std::make_shared<MyCryptoLibrary::SHA1>()),
      _ipadV{std::vector<unsigned char>(SHA1_BLOCK_SIZE, _ipad)},
      _opadV{std::vector<unsigned char>(SHA1_BLOCK_SIZE, _opad)} {}
/******************************************************************************/
MyCryptoLibrary::HMAC_SHA1::~HMAC_SHA1() {}
/******************************************************************************/
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
std::vector<unsigned char>
MyCryptoLibrary::HMAC_SHA1::hmac(const std::vector<unsigned char> &key,
                                 const std::vector<unsigned char> &message) {
  std::vector<unsigned char> hmac;
  _keyBlock = computeBlockSizedKey(key, SHA1_BLOCK_SIZE);
  std::vector<unsigned char> o_key_pad, i_key_pad;
  for (std::size_t i = 0; i < SHA1_BLOCK_SIZE; ++i) {
    o_key_pad.push_back(_keyBlock[i] ^ _opadV[i]);
    i_key_pad.push_back(_keyBlock[i] ^ _ipadV[i]);
  }
  std::vector<unsigned char> innerHashContent = i_key_pad;
  innerHashContent.insert(innerHashContent.end(), message.begin(),
                          message.end());
  std::vector<unsigned char> innerHash = _sha1->hash(innerHashContent);
  std::vector<unsigned char> hmacHashContent = o_key_pad;
  hmacHashContent.insert(hmacHashContent.end(), innerHash.begin(),
                         innerHash.end());
  return _sha1->hash(hmacHashContent);
}
/******************************************************************************/
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
std::vector<unsigned char> MyCryptoLibrary::HMAC_SHA1::computeBlockSizedKey(
    const std::vector<unsigned char> &key, const std::size_t blockSize) {
  _keyBlock = key;
  if (_keyBlock.size() > SHA1_BLOCK_SIZE) {
    _keyBlock = _sha1->hash(key);
  }
  if (_keyBlock.size() < SHA1_BLOCK_SIZE) {
    _keyBlock.resize(SHA1_BLOCK_SIZE, 0);
  }
  return _keyBlock;
}
/******************************************************************************/