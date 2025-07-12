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
                                       const std::size_t ivLength,
                                       const std::string &groupNameDH)
    : _diffieHellmanAM(std::make_unique<MyCryptoLibrary::DiffieHellman>(
          debugFlag, _parameterInjection, groupNameDH)),
      _serverNonceHexAM(
          EncryptionUtility::generateCryptographicNonce(nonceSize)),
      _clientNonceHexAM{clientNonceHex}, _clientIdAM{clientId},
      _ivAM{EncryptionUtility::generateRandomIV(ivLength)} {};
/******************************************************************************/
MallorySessionData::MallorySessionData(const std::size_t nonceSize,
                                       const std::string &clientNonceHex,
                                       const std::string &clientId,
                                       const bool debugFlag,
                                       const std::size_t ivLength,
                                       const std::string &groupNameDH,
                                       const bool parameterInjection)
    : _diffieHellmanAM(std::make_unique<MyCryptoLibrary::DiffieHellman>(
          debugFlag, parameterInjection, groupNameDH)),
      _serverNonceHexAM(
          EncryptionUtility::generateCryptographicNonce(nonceSize)),
      _clientNonceHexAM{clientNonceHex}, _clientIdAM{clientId},
      _ivAM{EncryptionUtility::generateRandomIV(ivLength)},
      _parameterInjection{parameterInjection} {};
/******************************************************************************/
MallorySessionData::~MallorySessionData() {}
/******************************************************************************/
