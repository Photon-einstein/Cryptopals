#ifndef MALLORY_SESSION_DATA_HPP
#define MALLORY_SESSION_DATA_HPP

#include "Client.hpp"
#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct MallorySessionData {
  explicit MallorySessionData(const std::size_t nonceSize,
                              const std::string &clientNonceHex,
                              const std::string &clientId, const bool debugFlag,
                              const std::size_t ivLength,
                              const std::string &groupNameDH);

  explicit MallorySessionData(const std::size_t nonceSize,
                              const std::string &clientNonceHex,
                              const std::string &clientId, const bool debugFlag,
                              const std::size_t ivLength,
                              const std::string &groupNameDH,
                              const bool parameterInjection);

  ~MallorySessionData();

  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellmanAM;
  // Client (Alice) - Mallory channel
  std::string _serverNonceHexAM;
  std::string _clientNonceHexAM;
  std::string _derivedKeyHexAM;
  std::string _clientIdAM; // transparent in this attack
  std::vector<uint8_t> _ivAM;
  // Client (Mallory) - Server channel
  std::string _sessionIdMS;
  std::unique_ptr<Client> _fakeClientMS;
  bool _parameterInjection{false};
};

#endif // MALLORY_SESSION_DATA_HPP