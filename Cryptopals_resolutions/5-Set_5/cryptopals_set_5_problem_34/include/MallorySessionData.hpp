#ifndef MALLORY_SESSION_DATA_HPP
#define MALLORY_SESSION_DATA_HPP

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct MallorySessionData {
  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _AMdiffieHellman;
  // Client (Alice) - Mallory channel
  std::string _AMserverNonceHex;
  std::string _AMclientNonceHex;
  std::string _AMderivedKeyHex;
  std::string _AMclientId; // transparent in this attack
  std::vector<uint8_t> _AMiv;
  // Client (Mallory) - Server channel
  std::string _MSserverNonceHex;
  std::string _MSclientNonceHex;
  std::string _MSderivedKeyHex;
  std::vector<uint8_t> _MSiv;

  MallorySessionData(const std::size_t nonceSize,
                     const std::string &clientNonceHex,
                     const std::string &clientId, const bool debugFlag,
                     const std::size_t ivLength)
      : _AMdiffieHellman(
            std::make_unique<MyCryptoLibrary::DiffieHellman>(debugFlag)),
        _AMserverNonceHex(
            EncryptionUtility::generateCryptographicNonce(nonceSize)),
        _AMclientNonceHex{clientNonceHex}, _AMclientId{clientId},
        _AMiv{EncryptionUtility::generateRandomIV(ivLength)} {};
};

#endif // MALLORY_SESSION_DATA_HPP