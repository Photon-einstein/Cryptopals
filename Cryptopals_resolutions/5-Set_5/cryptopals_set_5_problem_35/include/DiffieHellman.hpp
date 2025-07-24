#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "DhParametersLoader.hpp"
#include "MessageExtractionFacility.hpp"

namespace MyCryptoLibrary {

class DiffieHellman {
public:
  /* constructor / destructor*/
  /**
   * @brief This method will execute the constructor of the DiffieHellman
   * object.
   *
   * This method will execute the constructor of the DiffieHellman object when a
   * group name is given as an input parameter.
   *
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param groupName The group name to be used in the DH key exchange protocol,
   * to get the values of 'p' and 'g'.
   *
   * @throw runtime_error if the group name is null or invalid.
   */
  explicit DiffieHellman(const bool debugFlag, const std::string &groupName);

  /**
   * @brief This method will execute the constructor of the DiffieHellman
   * object.
   *
   * This method will execute the constructor of the DiffieHellman object when
   * the input parameters 'p' and 'g' are given.
   *
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param p The prime p to be used in the Diffie Hellman key exchange
   * protocol.
   * @param g The generator g to be used in the Diffie Hellman key exchange
   * protocol.
   *
   * @throw runtime_error if the prime p or generator g are null.
   */
  explicit DiffieHellman(const bool debugFlag, const std::string &p,
                         const std::string &g);

  /**
   * @brief This method will perform the destruction of the DiffieHellman
   * object.
   *
   * This method will perform the destruction of the DiffieHellman object,
   * releasing all the resources and memory used.
   */
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
   * @return The symmetric key.
   * @throws std::runtime_error if the Diffie Hellman key exchange protocol
   * has failed.
   */
  const std::vector<uint8_t> &getSymmetricKey() const;

  /**
   * @brief This method returns the expected confirmation message of a
   * successful Diffie Hellman key exchange.
   *
   * @return Expected confirmation message of a successful Diffie Hellman's key
   * exchange.
   * @throws std::runtime_error if the confirmation message is empty.
   */
  const std::string &getConfirmationMessage() const;

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Diffie Hellman key exchange protocol are available.
   *
   * @return The filename where the public configurations of the Diffie Hellman
   * key exchange protocol are available.
   * @throws std::runtime_error if the DH parameters filename is empty.
   */
  const std::string &getDhParametersFilenameLocation() const;

  /**
   * @brief This method returns the prime p used in the Diffie Hellman key
   * exchange protocol.
   *
   * @return The prime p, in hexadecimal format.
   * @throws std::runtime_error if the prime p is not set.
   */
  const std::string getPrimeP() const;

  /**
   * @brief This method returns the generator g used in the Diffie Hellman key
   * exchange protocol.
   *
   * @return The generator g, in hexadecimal format.
   * @throws std::runtime_error if the generator g is not set.
   */
  const std::string getGeneratorG() const;

  /**
   * @brief This method will test if the guess of the shared secret match the
   * the real value.
   *
   * This method will test if the guess of the shared secret match the
   * the real value of the raw shared secret.
   *
   * @param sharedSecretRawGuessHex The guess of the raw shared secret in
   * hexadecimal format.
   *
   * @return True if the values match, false otherwise.
   */
  bool testValueRawSharedSecret(const std::string &sharedSecretRawGuessHex);

  /**
   * @brief This method will test if the guess of the shared secret match the
   * the real value, that is assumed to be p-1.
   *
   * This method will test if the guess of the shared secret match the
   * the real value of the raw shared secret.
   *
   * @return True if the values match, false otherwise.
   */
  bool testValueRawSharedSecretNegativeHypothesis();

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
  std::string _derivedSymmetricKeyHex{};
  const std::string _confirmationMessage{"Key exchange complete"};
  std::string _groupName;
};

} // namespace MyCryptoLibrary

#endif // DIFFIE_HELLMAN_HPP
