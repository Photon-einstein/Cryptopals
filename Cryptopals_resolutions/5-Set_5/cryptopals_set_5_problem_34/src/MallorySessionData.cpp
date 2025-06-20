#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MallorySessionData.hpp"

/* constructor / destructor */
MallorySessionData::MallorySessionData(const std::size_t nonceSize,
                                       const std::string &clientNonceHex,
                                       const std::string &clientId,
                                       const bool debugFlag,
                                       const std::size_t ivLength)
    : _AMdiffieHellman(
          std::make_unique<MyCryptoLibrary::DiffieHellman>(debugFlag)),
      _AMserverNonceHex(
          EncryptionUtility::generateCryptographicNonce(nonceSize)),
      _AMclientNonceHex{clientNonceHex}, _AMclientId{clientId},
      _AMiv{EncryptionUtility::generateRandomIV(ivLength)} {};
/******************************************************************************/
MallorySessionData::~MallorySessionData() {}
/******************************************************************************/
