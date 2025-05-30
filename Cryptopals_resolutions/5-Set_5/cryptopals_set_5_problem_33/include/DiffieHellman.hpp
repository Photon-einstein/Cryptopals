#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "MessageExtractionFacility.hpp"

namespace MyCryptoLibrary {

class DiffieHellman {
public:
  /* constructor / destructor*/
  DiffieHellman(const bool debugFlag);
  ~DiffieHellman();

  /* public methods */

  /**
   * @brief This method will return the public key.
   *
   * This method will return the public key used at the Diffie Hellman
   * key exchange protocol.
   *
   * @return The public key (hex) in a string format.
   */
  const std::string getPublicKey();

  /**
   * @brief This method will return the group name.
   *
   * This method will return the group name used at the Diffie Hellman
   * key exchange protocol.
   *
   * @return The group name in a string format.
   */
  const std::string getGroupName();

  /**
   * @brief This method will derive a symmetric encryption key.
   *
   * This method will derive a symmetric encryption key as the derived
   * shared secret from the execution of the Diffie Hellman Key Exchange.
   *
   * @param peerPublicKeyHex The peer public key (hex).
   * @param serverNonceHex  The server nonce (hex).
   * @param clientNonceHex  The client nonce (hex).
   *
   * @return The symmetric encryption key (hex) in a string format.
   */
  const std::string deriveSharedSecret(const std::string &peerPublicKeyHex,
                                       const std::string &serverNonceHex,
                                       const std::string &clientNonceHex);

private:
  /* private methods */

  /**
   * @brief This method will generate a private key.
   *
   * This method will generate a private key to be used at a Diffie
   * Hellman key exchange protocol.
   */
  void generatePrivateKey();

  /**
   * @brief This method will generate a public key.
   *
   * This method will generate a public key to be used at a Diffie
   * Hellman key exchange protocol. A = g^a mod p
   */
  void generatePublicKey();

  /* private members */
  const std::string _dhParametersFilename{"./../input/dh_parameters.json"};
  DHParametersLoader::DHParameters _dhParameter;
  MessageExtractionFacility::UniqueBIGNUM _p, _g, _privateKey, _publicKey,
      _sharedSecret;
  bool _debugFlag;
};

} // namespace MyCryptoLibrary

#endif // DIFFIE_HELLMAN_HPP
