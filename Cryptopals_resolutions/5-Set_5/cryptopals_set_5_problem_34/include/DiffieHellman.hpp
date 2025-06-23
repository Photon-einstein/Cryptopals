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
  explicit DiffieHellman(const bool debugFlag, const std::string &groupName);
  explicit DiffieHellman(const bool debugFlag,
                         const bool publicKeyDeterministic,
                         const std::string &groupName);
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
  const std::string getPublicKey() const;

  /**
   * @brief This method will return the group name.
   *
   * This method will return the group name used at the Diffie Hellman
   * key exchange protocol.
   *
   * @return The group name in a string format.
   */
  const std::string &getGroupName() const;

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
   * @throws std::runtime_error if there is an error in the derivation of
   * the shared secret.
   */
  const std::string deriveSharedSecret(const std::string &peerPublicKeyHex,
                                       const std::string &serverNonceHex,
                                       const std::string &clientNonceHex);

  /**
   * @brief This method returns the symmetric key after the Diffie
   * Hellman key exchange protocol has been completed.
   *
   *
   * @return Symmetric key
   * @throws std::runtime_error if the Diffie Hellman key exchange protocol
   * has still not complete.
   */
  const std::vector<uint8_t> &getSymmetricKey() const;

  /**
   * @brief This method returns the expected confirmation message of successful
   * Diffie Hellman key exchange.
   *
   * @return Expected confirmation message of a successful Diffie Hellman key
   * exchange.
   * @throws std::runtime_error if the confirmation message is empty.
   */
  const std::string &getConfirmationMessage() const;

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Diffie Hellman key exchange protocol are available.
   *
   * @return Filename where the public configurations of the Diffie Hellman key
   * exchange protocol are available.
   * @throws std::runtime_error if the DH parameters filename is empty.
   */
  const std::string &getDhParametersFilenameLocation() const;

private:
  /* private methods */

  /**
   * @brief This method will generate a private key.
   *
   * This method will generate a private key to be used at a Diffie
   * Hellman key exchange protocol.
   *
   * @throws std::runtime_error if there is an error in the generation of the
   * private key.
   */
  void generatePrivateKey();

  /**
   * @brief This method will generate a public key.
   *
   * This method will generate a public key to be used at a Diffie
   * Hellman key exchange protocol. A = g^a mod p
   *
   * @throws std::runtime_error if there is an error in the generation of
   * the public key.
   */
  void generatePublicKey();

  /* private members */
  const std::string _dhParametersFilename{"../input/DhParameters.json"};
  DhParametersLoader::DhParameters _dhParameter;
  MessageExtractionFacility::UniqueBIGNUM _p, _g, _privateKey, _publicKey,
      _sharedSecret;
  bool _debugFlag;
  std::vector<uint8_t> _derivedSymmetricKey;
  std::string _derivedSymmetricKeyHex = "";
  const std::string _confirmationMessage{"Key exchange complete"};
  const bool _publicKeyDeterministic{false};
  std::string _groupName;
};

} // namespace MyCryptoLibrary

#endif // DIFFIE_HELLMAN_HPP
