#ifndef MALLORY_SESSION_DATA_HPP
#define MALLORY_SESSION_DATA_HPP

#include "Client.hpp"
#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct MallorySessionData {
  MallorySessionData(const std::size_t nonceSize,
                     const std::string &clientNonceHex,
                     const std::string &clientId, const bool debugFlag,
                     const std::size_t ivLength);

  ~MallorySessionData();

  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _AMdiffieHellman;
  // Client (Alice) - Mallory channel
  std::string _AMserverNonceHex;
  std::string _AMclientNonceHex;
  std::string _AMderivedKeyHex;
  std::string _AMclientId; // transparent in this attack
  std::vector<uint8_t> _AMiv;
  // Client (Mallory) - Server channel
  std::string _MSsessionId;
  std::unique_ptr<Client> _MSfakeClient;
};

#endif // MALLORY_SESSION_DATA_HPP