#ifndef SESSION_DATA_HPP
#define SESSION_DATA_HPP

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"

struct SessionData {

  // Server's constructor side
  /**
   * @brief This method will execute the constructor of the SessionData
   * structure on the server side.
   *
   * This method will execute the constructor of the SessionData structure used
   * by the Server object.
   *
   * @param nonceSize The nonce size used in the Diffie Hellman key exchange
   * protocol.
   * @param clientNonceHex The client nonce received in hexadecimal format.
   * @param clientId The client ID that is using this session.
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param ivLength The length of the initialization vector (IV) used in the
   * symmetric encryption AES-256-CBC mode, in bytes.
   * @param p The prime p used in the Diffie Hellman key exchange protocol.
   * @param g The generator g used in the Diffie Hellman key exchange protocol.
   *
   * @throw runtime_error if clientId or groupNameDH are empty.
   */
  explicit SessionData(const std::size_t nonceSize,
                       const std::string &clientNonceHex,
                       const std::string &clientId, const bool debugFlag,
                       const std::size_t ivLength, const std::string &p,
                       const std::string &g);

  // Client's constructor side
  /**
   * @brief This method will execute the constructor of the SessionData
   * structure on the client side.
   *
   * This method will execute the constructor of the SessionData structure used
   * by the client object.
   *
   * @param diffieHellman The DiffieHellman object to be used in this session.
   * @param serverNonceHex The server nonce received in hexadecimal format.
   * @param clientNonceHex The client nonce in hexadecimal format.
   * @param iv The initialization vector (iv) used in the AES-256-CBC mode.
   */
  explicit SessionData(
      std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman,
      const std::string &serverNonceHex, const std::string &clientNonceHex,
      const std::vector<uint8_t> &iv);

  /**
   * @brief This method will perform the destruction of the SessionData
   * structure.
   *
   * This method will perform the destruction of the SessionData structure,
   * releasing all the resources and memory used.
   */
  ~SessionData();

  std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellman;
  std::string _serverNonceHex;
  std::string _clientNonceHex;
  std::string _derivedKeyHex;
  std::string _clientId;
  std::vector<uint8_t> _iv;
  std::string _groupNameDH;
};

#endif // SESSION_DATA_HPP