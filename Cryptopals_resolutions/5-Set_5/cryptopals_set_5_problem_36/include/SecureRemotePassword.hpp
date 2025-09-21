#ifndef SECURE_REMOTE_PASSWORD_HPP
#define SECURE_REMOTE_PASSWORD_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "EncryptionUtility.hpp"
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
   * @brief Calculates and stores the SRP multiplier parameter k for each group.
   *
   * This method iterates over all loaded SRP parameter groups and computes the
   * multiplier parameter k for each group using the formula k = H(N | PAD(g)),
   * where H is the group's hash function, N is the group prime, and PAD(g) is
   * the generator g left-padded with zeros to match the length of N. The
   * computed k values are stored in the internal _kMap for efficient retrieval
   * during protocol operations.
   *
   * This method is typically called during object construction or
   * initialization to ensure that all required k values are available for SRP
   * calculations.
   *
   * @return A map from group ID (unsigned int) to the corresponding
   * UniqueBIGNUM representing k.
   * @throws std::runtime_error if any required parameters are missing or if
   * calculation fails.
   */
  static std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM>
  calculateKMultiplierParameters();

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Secure Remote Password protocol are available.
   *
   * @return Filename where the public configurations of the Secure Remote
   * Password protocol are available.
   */
  static const std::string &getSrpParametersFilenameLocation();

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
  static const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> &
  getKMap();

  /**
   * @brief Returns a constant reference to the map of SRP parameter groups.
   *
   * This method provides access to the internal map that associates each SRP
   * group ID with its corresponding parameters loaded from the configuration
   * file.
   *
   * @return A constant reference to the map from group ID (unsigned int) to
   * SrpParametersLoader::SrpParameters.
   */
  const std::map<unsigned int, SrpParametersLoader::SrpParameters> &
  getSrpParametersMap() const;

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
   * @brief This method will perform the calculation v = g^x mod N.
   *
   * @param xHex The value of x, as a hexadecimal string.
   * @param nHex The value of the large prime N, as a hexadecimal string.
   * @param g The value of the generator g.
   *
   * @return The result of v = g^x mod N, in hexadecimal format.
   * @throw std::runtime_error If the calculation fails.
   */
  static const std::string calculateV(const std::string &xHex,
                                      const std::string &nHex, unsigned int g);

  /**
   * @brief Calculates a hash digest of the concatenation of two values.
   *
   * @param hashName The hash algorithm to use (e.g., "SHA-256").
   * @param left The left value in plaintext
   * @param right The right value in plaintext
   * @return The hash digest in hexadecimal format.
   */
  static const std::string calculateHashConcat(const std::string &hashName,
                                               const std::string &left,
                                               const std::string &right);

  /**
   * @brief This method will perform the following calculation:
   * x = H(s | P).
   *
   * This method will perform the following calculation:
   * x = H(s | P).
   * Clarification:
   * - H: hash algorithm;
   * - s: salt;
   * - P: password;
   * - x: output of the hash;
   *
   * @param hash The hash algorithm used in this calculation.
   * @param password The password used in this calculation, received in
   * plaintext.
   * @param salt The salt used in this calculation, received in hexadecimal
   * format
   *
   * @return The result of H(s | P) in hexadecimal format.
   */
  static const std::string calculateX(const std::string &hash,
                                      const std::string &password,
                                      const std::string &salt);

  /**
   * @brief This method calculates the session key S for the client in the SRP
   * protocol.
   *
   * Formula: S = (B - k * g^x) ^ (a + u * x) mod N
   *
   * @param BHex The hexadecimal representation of the server's public key B.
   * @param kHex The hexadecimal representation of the SRP multiplier parameter
   * k.
   * @param g The SRP generator.
   * @param xHex The hexadecimal representation of the client's private value x.
   * @param aHex The hexadecimal representation of the client's private key a.
   * @param uHex The hexadecimal representation of the SRP scrambling parameter
   * u.
   * @param nHex The hexadecimal representation of the SRP modulus N.
   * @return The session key S as a hexadecimal string.
   * @throw std::runtime_error if any of the calculations fail.
   */
  static std::string
  calculateS(const std::string &BHex, const std::string &kHex, unsigned int g,
             const std::string &xHex, const std::string &aHex,
             const std::string &uHex, const std::string &nHex);

  /**
   * @brief This method calculates the session key K for the client in the SRP
   * protocol.
   *
   * Formula: K = H(S)
   * Clarification:
   * - H: hash algorithm;
   * - S: shared secret in hexadecimal format;
   *
   * @param hash The hash algorithm (e.g., "SHA-256").
   * @param SHex The shared secret, in hexadecimal format.
   * @return The session key K as a hexadecimal string.
   * @throw std::runtime_error if any of the calculations fail.
   */
  static std::string calculateK(const std::string &hash,
                                const std::string &SHex);

private:
  /* private methods */

  /* private members */
  bool _debugFlag;
  static const std::string _srpParametersFilename;
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _groupId;
  static unsigned int _minSizePrivateKey;
  static std::unordered_map<std::string, EncryptionUtility::HashFn> _hashMap;
  static const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM>
      _kMap;
};

} // namespace MyCryptoLibrary

#endif // SECURE_REMOTE_PASSWORD_HPP
