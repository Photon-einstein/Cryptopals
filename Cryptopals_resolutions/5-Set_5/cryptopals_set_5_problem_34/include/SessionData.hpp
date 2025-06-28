#ifndef SESSION_DATA_HPP
#define SESSION_DATA_HPP

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct SessionData {
  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellman;
  std::string _serverNonceHex;
  std::string _clientNonceHex;
  std::string _derivedKeyHex;
  std::string _clientId;
  std::vector<uint8_t> _iv;
  std::string _groupNameDH;

  // Server's constructor side
  SessionData(const std::size_t nonceSize, const std::string &clientNonceHex,
              const std::string &clientId, const bool debugFlag,
              const std::size_t ivLength, const std::string &groupNameDH)
      : _diffieHellman(std::make_unique<MyCryptoLibrary::DiffieHellman>(
            debugFlag, groupNameDH)),
        _serverNonceHex(
            EncryptionUtility::generateCryptographicNonce(nonceSize)),
        _clientNonceHex{clientNonceHex}, _clientId{clientId},
        _iv{EncryptionUtility::generateRandomIV(ivLength)},
        _groupNameDH{groupNameDH} {};

  // Client's constructor side
  SessionData(std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman,
              const std::string &serverNonceHex,
              const std::string &clientNonceHex, const std::vector<uint8_t> &iv)
      : _diffieHellman(std::move(diffieHellman)),
        _serverNonceHex{serverNonceHex}, _clientNonceHex{clientNonceHex},
        _iv{iv} {};
};

#endif // SESSION_DATA_HPP