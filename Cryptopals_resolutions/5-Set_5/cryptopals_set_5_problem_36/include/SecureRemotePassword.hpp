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
   * @brief This method will generate a private key.
   *
   * This method will generate a private key to be used at a SRP protocol.
   * Requirements of the private key:
   * - should be at in the range [1, N-1];
   * - should be at least minSizeBits;
   *
   * @param nHex N in hexadecimal format.
   * @param minSizeBits The minimum amount of bits that the private key should
   * have.
   *
   * @return The private key in a string, in hexadecimal format.
   */
  static std::string generatePrivateKey(const std::string &nHex,
                                        const unsigned int minSizeBits);

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

  /**
   * @brief This method does the validation of the public key.
   *
   * This method does the validation of the public key. It enforces:
   * 1 < public key < N
   *
   * @param publicKeyHex The public key (a or b) in hex.
   * @param nHex The group prime N in hexadecimal format.
   * @return True if the validation passes, false otherwise.
   */
  static bool validatePublicKey(const std::string &publicKeyHex,
                                const std::string &nHex);

  /**
   * @brief Calculates the SRP multiplier parameter k = H(N | PAD(g)).
   *
   * This method computes the SRP parameter k as specified in RFC 5054:
   *   k = H(N | PAD(g))
   * where H is the agreed hash function, N is the group prime (as a hex
   * string), and PAD(g) is the generator g left-padded with zeros to the length
   * of N. The result is returned as a UniqueBIGNUM.
   *
   * @param nHex The group prime N in hexadecimal format.
   * @param gHex The generator g in hexadecimal format.
   * @param hashName The name of the hash function to use (e.g., "SHA-256").
   * @return The computed k parameter as a UniqueBIGNUM.
   * @throws std::invalid_argument if N or g is empty, or if g >= N.
   * @throws std::runtime_error if conversion or hashing fails.
   */
  static MessageExtractionFacility::UniqueBIGNUM
  calculateK(const std::string &nHex, const std::string &gHex,
             const std::string &hashName);

  /**
   * @brief Computes the SRP scrambling parameter u = H(A | B).
   *
   * @param hashName The hash function name (e.g., "SHA-256").
   * @param aHex The public key A in hexadecimal format.
   * @param bHex The public key B in hexadecimal format.
   * @return The scrambling parameter u as a hexadecimal string.
   * @throws std::runtime_error if the hash function is not supported.
   */
  static std::string calculateU(const std::string &hashName,
                                const std::string &aHex,
                                const std::string &bHex);

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
