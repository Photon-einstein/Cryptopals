#ifndef MALLORY_SESSION_DATA_HPP
#define MALLORY_SESSION_DATA_HPP

#include "Client.hpp"
#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct MallorySessionData {
  /**
   * @brief This method will execute the constructor of the MallorySessionData
   * structure.
   *
   * This method will execute the constructor of the MallorySessionData
   * structure used by the MalloryServer object.
   *
   * @param nonceSize The nonce size used in the Diffie Hellman key exchange
   * protocol.
   * @param clientNonceHex The client nonce received in hexadecimal format.
   * @param clientId The client id that is using this session.
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param ivLength The length of the initialization vector (IV) used in the
   * symmetric encryption AES-256-CBC mode, in bytes.
   * @param p The prime p used in the Diffie Hellman key exchange protocol.
   * @param g The generator g used in the Diffie Hellman key exchange protocol.
   *
   * @throw runtime_error if clientId or groupNameDH are empty.
   */
  explicit MallorySessionData(const std::size_t nonceSize,
                              const std::string &clientNonceHex,
                              const std::string &clientId, const bool debugFlag,
                              const std::size_t ivLength, const std::string &p,
                              const std::string &g);

  /**
   * @brief This method will perform the destruction of the MallorySessionData
   * structure.
   *
   * This method will perform the destruction of the MallorySessionData
   * structure, releasing all the resources and memory used.
   */
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
};

#endif // MALLORY_SESSION_DATA_HPP