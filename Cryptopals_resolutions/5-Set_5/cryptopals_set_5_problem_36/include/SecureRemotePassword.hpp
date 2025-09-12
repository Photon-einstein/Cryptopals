#ifndef SECURE_REMOTE_PASSWORD_HPP
#define SECURE_REMOTE_PASSWORD_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "MessageExtractionFacility.hpp"
#include "SrpParametersLoader.hpp"

namespace MyCryptoLibrary {

class SecureRemotePassword {
public:
  /* constructor / destructor*/

  /**
   * @brief This method will execute the constructor of the SecureRemotePassword
   * object.
   *
   * This method will perform the constructor of the SecureRemotePassword object
   * when a group name is used in its constructor.
   *s
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   *
   */
  explicit SecureRemotePassword(const bool debugFlag);

  /**
   * @brief This method will perform the destruction of the SecureRemotePassword
   * object.
   *
   * This method will perform the destruction of the SecureRemotePassword
   * object, releasing all the resources and memory used.
   */
  ~SecureRemotePassword();

  /* public methods */

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Secure Remote Password protocol are available.
   *
   * @return Filename where the public configurations of the Secure Remote
   * Password protocol are available.
   */
  const std::string &getSrpParametersFilenameLocation();

  /**
   * @brief This method returns the minimum size of a private key in bits,
   * according to the SRP protocol.
   *
   * @return The minimum size of a private key at the SPP protocol, in bits.
   */
  const unsigned int &getMinSizePrivateKey();

  /**
   * @brief Returns a constant reference to the map of SRP multiplier parameters
   * k.
   *
   * This method provides access to the internal map that associates each SRP
   * group ID with its corresponding multiplier parameter k, where k is
   * calculated as k = H(N | PAD(g)) according to RFC 5054. The map is populated
   * during construction of the SecureRemotePassword object and is used for
   * efficient retrieval of k during protocol operations.
   *
   * @return A constant reference to the map from group ID (unsigned int) to the
   *         corresponding UniqueBIGNUM representing k.
   */
  const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> &
  getKMap() const;

  /**
   * @brief Calculates the SRP public key (A or B).
   *
   * For the client: A = g^a mod N
   * For the server: B = (k*v + g^b) mod N
   *
   * @param privateKeyHex The private key (a or b) in hex.
   * @param nHex The group prime N in hexadecimal format.
   * @param gHex The generator g in hexadecimal format.
   * @param isServer If true, computes B (server); if false, computes A
   * (client).
   * @param k Optional: the SRP multiplier parameter as BIGNUM (required for B).
   * @param vHex Optional: the verifier v in hex (required for B).
   * @return The public key (A or B) as a hexadecimal string.
   * @throws std::runtime_error if constraints are not met.
   */
  static std::string calculatePublicKey(const std::string &privateKeyHex,
                                        const std::string &nHex,
                                        const std::string &gHex, bool isServer,
                                        const BIGNUM *k = nullptr,
                                        const std::string &vHex = "");

private:
  /* private methods */

  /* private members */
  bool _debugFlag;
  const std::string _srpParametersFilename{"../input/SrpParameters.json"};
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _groupId;
  static unsigned int _minSizePrivateKey;
  std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> _kMap;
};

} // namespace MyCryptoLibrary

#endif // SECURE_REMOTE_PASSWORD_HPP
