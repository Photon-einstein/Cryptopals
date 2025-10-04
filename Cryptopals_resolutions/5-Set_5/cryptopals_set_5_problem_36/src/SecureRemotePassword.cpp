#include <algorithm>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

#include "./../include/SecureRemotePassword.hpp"

/* static fields initialization */
unsigned int MyCryptoLibrary::SecureRemotePassword::_minSizePrivateKey = 256;
std::unordered_map<std::string, EncryptionUtility::HashFn>
    MyCryptoLibrary::SecureRemotePassword::_hashMap =
        EncryptionUtility::getHashMap();

const std::string
    MyCryptoLibrary::SecureRemotePassword::_srpParametersFilename =
        "../input/SrpParameters.json";

const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM>
    MyCryptoLibrary::SecureRemotePassword::_kMap =
        MyCryptoLibrary::SecureRemotePassword::calculateKMultiplierParameters();

/* constructor / destructor */

/**
 * @brief This method will execute the constructor of the SecureRemotePassword
 * object.
 *
 * This method will perform the constructor of the SecureRemotePassword object
 * when a group name is used in its constructor.
 *s
 * @param debugFlag The boolean flag to decide if aggressive prints should be
 * displayed into the standard output, created for troubleshooting purposes.
 */
MyCryptoLibrary::SecureRemotePassword::SecureRemotePassword(
    const bool debugFlag)
    : _debugFlag{debugFlag},
      _srpParametersMap{SrpParametersLoader::loadSrpParameters(
          getSrpParametersFilenameLocation())} {
  if (_debugFlag) {
    std::cout << std::endl;
  }
  for (const auto &entry : _srpParametersMap) {
    const unsigned int groupId = entry.first;
    if (_debugFlag) {
      std::cout << "k[group ID = " << groupId << "] = "
                << MessageExtractionFacility::BIGNUMToHex(
                       _kMap.at(groupId).get())
                << std::endl;
    }
  }
  if (_debugFlag) {
    std::cout << std::endl;
  }
}
/******************************************************************************/
MyCryptoLibrary::SecureRemotePassword::~SecureRemotePassword() {}
/******************************************************************************/
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
std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM>
MyCryptoLibrary::SecureRemotePassword::calculateKMultiplierParameters() {
  std::map<unsigned int, SrpParametersLoader::SrpParameters> srpParametersMap{
      SrpParametersLoader::loadSrpParameters(
          getSrpParametersFilenameLocation())};
  std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> kMap;
  for (const auto &entry : srpParametersMap) {
    const unsigned int groupId{entry.first};
    const SrpParametersLoader::SrpParameters &params{entry.second};
    const std::string gHex{MessageExtractionFacility::uintToHex(params._g)};
    kMap[groupId] = calculateK(params._nHex, gHex, params._hashName);
  }
  return kMap;
}
/******************************************************************************/
/**
 * @brief This method returns the location of the file where the public
 * configurations of the Secure Remote Password protocol are available.
 *
 * @return Filename where the public configurations of the Secure Remote
 * Password protocol are available.
 */
const std::string &
MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::invalid_argument(
        "Secure Remote Password log | "
        "getSrpParametersFilenameLocation(): public SRP "
        "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
/******************************************************************************/
/**
 * @brief This method returns the minimum size of a private key in bits,
 * according to the SRP protocol.
 *
 * @return The minimum size of a private key at the SPP protocol, in bits.
 */
const unsigned int &
MyCryptoLibrary::SecureRemotePassword::getMinSizePrivateKey() {
  if (_minSizePrivateKey <= 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getMinSizePrivateKey(): stored minSizePrivateKey "
                             "is invalid");
  }
  return _minSizePrivateKey;
}
/******************************************************************************/
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
MyCryptoLibrary::SecureRemotePassword::getKMap() {
  if (_kMap.empty()) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getKMap(): dictionary not initialized");
  }
  return _kMap;
}
/******************************************************************************/
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
MyCryptoLibrary::SecureRemotePassword::getSrpParametersMap() const {
  if (_kMap.empty()) {
    throw std::runtime_error(
        "Secure Remote Password log | "
        "getSrpParametersMap(): dictionary not initialized");
  }
  return _srpParametersMap;
}
/******************************************************************************/
/**
 * @brief This method will generate a private key.
 *
 * This method will generate a private key to be used at a SRP protocol.
 * Requirements of the private key:
 * - should be at in the range [1, N-1];
 * - should be at least minSizeBits;
 *
 * @param NHex N in hexadecimal format.
 * @param minSizeBits The minimum amount of bits that the private key should
 * have.
 *
 * @return The private key in a string, in hexadecimal format.
 */
std::string MyCryptoLibrary::SecureRemotePassword::generatePrivateKey(
    const std::string &NHex, const unsigned int minSizeBits) {
  if (NHex.empty() || minSizeBits <= 0) {
    throw std::invalid_argument(
        "SecureRemotePassword log | generatePrivateKey(): "
        "Invalid input parameters received.");
  }
  // Convert N from hex to BIGNUM
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  // Prepare context and result
  EncryptionUtility::BnCtxPtr ctx(BN_CTX_new());
  if (!ctx) {
    throw std::runtime_error("SecureRemotePassword log | generatePrivateKey(): "
                             "Failed to allocate BN_CTX.");
  }
  EncryptionUtility::BnPtr privateKey(BN_new());
  if (!privateKey) {
    throw std::runtime_error("SecureRemotePassword log | generatePrivateKey(): "
                             "Failed to allocate BIGNUM.");
  }
  int nBits{BN_num_bits(nBn.get())};
  if (minSizeBits > nBits) {
    throw std::runtime_error("SecureRemotePassword log | "
                             "generatePrivateKey(): minSizeBits greater "
                             "than the number of bits of N");
  }
  int bits{std::max(static_cast<int>(minSizeBits), nBits)};
  // Generate random private key: 1 <= privateKey < N, at least minSizeBits
  // bits
  while (true) {
    if (!BN_rand(privateKey.get(), bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
      throw std::runtime_error(
          "SecureRemotePassword::generatePrivateKey(): BN_rand failed.");
    }
    // Ensure 1 <= privateKey < N and at least minSizeBits bits
    if (BN_cmp(privateKey.get(), BN_value_one()) >= 0 &&
        BN_cmp(privateKey.get(), nBn.get()) < 0 &&
        BN_num_bits(privateKey.get()) >= static_cast<int>(minSizeBits)) {
      break;
    }
    // Otherwise, try again
  }
  // Convert to hex string
  return MessageExtractionFacility::BIGNUMToHex(privateKey.get());
}
/******************************************************************************/
/**
 * @brief Calculates the SRP public key (A or B).
 *
 * For the client: A = g^a mod N
 * For the server: B = (k*v + g^b) mod N
 *
 * @param privateKeyHex The private key (a or b) in hex.
 * @param NHex The group prime N in hexadecimal format.
 * @param gHex The generator g in hexadecimal format.
 * @param isServer If true, computes B (server); if false, computes A
 * (client).
 * @param k Optional: the SRP multiplier parameter as BIGNUM (required for B).
 * @param vHex Optional: the verifier v in hex (required for B).
 * @return The public key (A or B) as a hexadecimal string.
 * @throws std::runtime_error if constraints are not met.
 */
std::string MyCryptoLibrary::SecureRemotePassword::calculatePublicKey(
    const std::string &privateKeyHex, const std::string &NHex,
    const std::string &gHex, bool isServer, const BIGNUM *k,
    const std::string &vHex) {
  // Input parameter validation
  if (privateKeyHex.empty() || NHex.empty() || gHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculatePublicKey(): One or more required "
        "input parameters are empty.");
  }
  if (isServer && (!k || vHex.empty())) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculatePublicKey(): k or v is missing "
        "for server public key calculation.");
  }
  // Convert inputs to BIGNUMs
  MessageExtractionFacility::UniqueBIGNUM n{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  MessageExtractionFacility::UniqueBIGNUM g{
      MessageExtractionFacility::hexToUniqueBIGNUM(gHex)};
  MessageExtractionFacility::UniqueBIGNUM privateKey{
      MessageExtractionFacility::hexToUniqueBIGNUM(privateKeyHex)};
  EncryptionUtility::BnCtxPtr ctx(BN_CTX_new());
  if (!ctx)
    throw std::runtime_error("SRP: Failed to allocate BN_CTX.");

  EncryptionUtility::BnPtr result(BN_new());
  if (!result)
    throw std::runtime_error("SRP: Failed to allocate BIGNUM.");

  if (isServer) {
    // B = (k*v + g^b) mod N
    if (!k || vHex.empty()) {
      throw std::runtime_error(
          "Secure Remote Password log | calculatePublicKey(): k and v are "
          "required for B calculation.");
    }
    MessageExtractionFacility::UniqueBIGNUM v{
        MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
    EncryptionUtility::BnPtr kMultV(BN_new());
    if (!kMultV) {
      throw std::runtime_error(
          "Secure Remote Password log | calculatePublicKey(): Failed to "
          "allocate BIGNUM for k*V.");
    }
    if (!BN_mod_mul(kMultV.get(), k, v.get(), n.get(), ctx.get())) {
      throw std::runtime_error("SRP: BN_mod_mul failed for k*v.");
    }
    EncryptionUtility::BnPtr gPowB(BN_new());
    if (!gPowB) {
      throw std::runtime_error(
          "Secure Remote Password log | calculatePublicKey(): Failed to "
          "allocate BIGNUM for g^b.");
    }
    if (!BN_mod_exp(gPowB.get(), g.get(), privateKey.get(), n.get(),
                    ctx.get())) {
      throw std::runtime_error("SRP: BN_mod_exp failed for g^b.");
    }
    if (!BN_mod_add(result.get(), kMultV.get(), gPowB.get(), n.get(),
                    ctx.get())) {
      throw std::runtime_error(
          "Secure Remote Password log | calculatePublicKey(): BN_mod_add "
          "failed for B = kMultV + g^b mod N.");
    }
  } else {
    // A = g^a mod N
    if (!BN_mod_exp(result.get(), g.get(), privateKey.get(), n.get(),
                    ctx.get())) {
      throw std::runtime_error(
          "Secure Remote Password log | calculatePublicKey(): BN_mod_exp "
          "failed for A = g^a mod N.");
    }
  }
  // Enforce 1 < result < N
  if (BN_cmp(result.get(), BN_value_one()) <= 0 ||
      BN_cmp(result.get(), n.get()) >= 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "calculatePublicKey(): Public key not in "
                             "valid range (1 < key < N).");
  }
  return MessageExtractionFacility::BIGNUMToHex(result.get());
}
/******************************************************************************/
/**
 * @brief This method does the validation of the public key.
 *
 * This method does the validation of the public key. It enforces:
 * 1 < public key < N
 *
 * @param publicKeyHex The public key (a or b) in hex.
 * @param NHex The group prime N in hexadecimal format.
 * @return True if the validation passes, false otherwise.
 */
bool MyCryptoLibrary::SecureRemotePassword::validatePublicKey(
    const std::string &publicKeyHex, const std::string &NHex) {
  // input parameter validation
  if (publicKeyHex.empty() || NHex.empty()) {
    std::cerr << "Secure Remote Password log | validatePublicKey(): parameters "
                 "received are empty."
              << std::endl;
    return false;
  }
  // Convert inputs to BIGNUMs
  MessageExtractionFacility::UniqueBIGNUM publicKey{
      MessageExtractionFacility::hexToUniqueBIGNUM(publicKeyHex)};
  MessageExtractionFacility::UniqueBIGNUM n{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EncryptionUtility::BnCtxPtr ctx(BN_CTX_new());
  if (BN_cmp(publicKey.get(), BN_value_one()) <= 0 ||
      BN_cmp(publicKey.get(), n.get()) >= 0) {
    std::cerr << "Secure Remote Password log | validatePublicKey(): Public key "
                 "not in valid range (1 < key < N)."
              << std::endl;
    return false;
  }
  return true;
}
/******************************************************************************/
/**
 * @brief Calculates the SRP multiplier parameter k = H(N | PAD(g)).
 *
 * This method computes the SRP parameter k as specified in RFC 5054:
 *   k = H(N | PAD(g))
 * where H is the agreed hash function, N is the group prime (as a hex
 * string), and PAD(g) is the generator g left-padded with zeros to the length
 * of N. The result is returned as a UniqueBIGNUM.
 *
 * @param NHex The group prime N in hexadecimal format.
 * @param gHex The generator g in hexadecimal format.
 * @param hashName The name of the hash function to use (e.g., "SHA-256").
 * @return The computed k parameter as a UniqueBIGNUM.
 * @throws std::invalid_argument if N or g is empty, or if g >= N.
 * @throws std::runtime_error if conversion or hashing fails.
 */
MessageExtractionFacility::UniqueBIGNUM
MyCryptoLibrary::SecureRemotePassword::calculateK(const std::string &NHex,
                                                  const std::string &gHex,
                                                  const std::string &hashName) {
  // input parameters validation
  if (NHex.empty() || gHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): N or g is empty.");
  }
  // 1. Convert N and g to bytes and validate parameters one more time
  std::vector<uint8_t> NBytes{MessageExtractionFacility::hexToBytes(NHex)};
  std::vector<uint8_t> gBytes{MessageExtractionFacility::hexToBytes(gHex)};
  if (NBytes.empty() ||
      NBytes.size() < 16) { // 16 bytes / 128 bits minimum for safety
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): N is too small or invalid.");
  } else if (gBytes.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): g is invalid.");
  }
  BIGNUM *nBn{BN_bin2bn(NBytes.data(), NBytes.size(), nullptr)};
  BIGNUM *gBn{BN_bin2bn(gBytes.data(), gBytes.size(), nullptr)};
  if (!nBn || !gBn) {
    BN_free(nBn);
    BN_free(gBn);
    throw std::runtime_error("SecureRemotePassword::calculateK: Failed to "
                             "convert N or g to BIGNUM.");
  } else if (BN_cmp(gBn, nBn) >= 0) {
    BN_free(nBn);
    BN_free(gBn);
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK: g must be less than N.");
  }
  BN_free(nBn);
  BN_free(gBn);
  // 2. Pad g to length of N
  std::vector<uint8_t> gPadded{
      EncryptionUtility::padLeft(gBytes, NBytes.size())};
  // 3. Concatenate N || PAD(g)
  std::vector<uint8_t> inputBytes(NBytes);
  inputBytes.insert(inputBytes.end(), gPadded.begin(), gPadded.end());
  // 5. Hash
  const auto &hashMap{EncryptionUtility::getHashMap()};
  auto it{hashMap.find(hashName)};
  if (it == hashMap.end()) {
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): Unsupported hash");
  }
  const std::string hashHex{it->second(std::string(
      reinterpret_cast<const char *>(inputBytes.data()), inputBytes.size()))};
  // 6. Convert Hex to BigNum
  return MessageExtractionFacility::hexToUniqueBIGNUM(hashHex);
}
/******************************************************************************/
/**
 * @brief This method will perform the calculation v = g^x mod N.
 *
 * @param xHex The value of x, as a hexadecimal string.
 * @param NHex The value of the large prime N, as a hexadecimal string.
 * @param g The value of the generator g.
 *
 * @return The result of v = g^x mod N, in hexadecimal format.
 * @throw std::runtime_error If the calculation fails.
 */
const std::string MyCryptoLibrary::SecureRemotePassword::calculateV(
    const std::string &xHex, const std::string &NHex, unsigned int g) {
  // input parameters validation
  if (xHex.empty() || NHex.empty() || g <= 1) {
    throw std::invalid_argument("SecureRemotePassword::calculateV(): invalid "
                                "input parameters received.");
  }
  // Allocate with RAII
  EncryptionUtility::BnCtxPtr ctx(BN_CTX_new());
  if (!ctx) {
    throw std::runtime_error("SecureRemotePassword log | calculateV(): "
                             "Failed to allocate BN_CTX.");
  }
  EncryptionUtility::BnPtr gBn(BN_new());
  EncryptionUtility::BnPtr vBn(BN_new());
  if (!gBn || !vBn) {
    throw std::runtime_error("SecureRemotePassword log | calculateV(): "
                             "Failed to allocate BIGNUMs.");
  }
  BIGNUM *xBn{nullptr};
  BIGNUM *nBn{nullptr};
  if (!BN_hex2bn(&xBn, xHex.c_str()) || !BN_hex2bn(&nBn, NHex.c_str())) {
    BN_free(xBn);
    BN_free(nBn);
    throw std::runtime_error("SecureRemotePassword log | calculateV(): Failed "
                             "to convert hex strings to BIGNUM.");
  }
  // Wrap xBn and nBn now that they're allocated
  EncryptionUtility::BnPtr xPtr(xBn);
  EncryptionUtility::BnPtr nPtr(nBn);
  BN_set_word(gBn.get(), g);
  // Compute v = g^x mod N
  if (!BN_mod_exp(vBn.get(), gBn.get(), xPtr.get(), nPtr.get(), ctx.get())) {
    throw std::runtime_error(
        "SecureRemotePassword log | calculateV(): BN_mod_exp failed.");
  }
  // Convert result to hex string
  EncryptionUtility::OsslStr vHex(BN_bn2hex(vBn.get()));
  if (!vHex) {
    throw std::runtime_error("SecureRemotePassword log | calculateV(): Failed "
                             "to convert result to hex.");
  }
  return std::string(vHex.get()); // safely copy to std::string
}
/******************************************************************************/
/**
 * @brief Calculates a hash digest of the concatenation of two values.
 *
 * @param hashName The hash algorithm to use (e.g., "SHA-256").
 * @param left The left value in plaintext
 * @param right The right value in plaintext
 * @return The hash digest in hexadecimal format.
 */
const std::string MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
    const std::string &hashName, const std::string &left,
    const std::string &right) {
  if (_hashMap.find(hashName) == _hashMap.end()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateHashConcat(): "
        "hash algorithm not recognized.");
  } else if (left.empty() || right.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateHashConcat(): "
        "invalid input parameters received, cannot be empty.");
  }
  const std::string digestX{_hashMap.at(hashName)(left + right)};
  return digestX;
}
/******************************************************************************/
/**
 * @brief Calculates the SRP private key 'x' according to RFC 5054.
 *
 * RFC 5054 formula:
 *   x = H(salt | H(username | ":" | password))
 * where H is the agreed hash function (e.g., SHA-1, SHA-256, SHA-384,
 * SHA-512), salt is provided in hexadecimal format, and username and password
 * are in plaintext.
 *
 * @param hashName The hash algorithm to use (e.g., "SHA-256").
 * @param username The username in plaintext.
 * @param password The password in plaintext.
 * @param saltHex The salt value in hexadecimal format.
 * @return The computed 'x' value as a hexadecimal string.
 * @throws std::invalid_argument if any input is empty or unsupported hash is
 * specified.
 */
const std::string MyCryptoLibrary::SecureRemotePassword::calculateX(
    const std::string &hashName, const std::string &username,
    const std::string &password, const std::string &saltHex) {
  // Validate input
  if (_hashMap.find(hashName) == _hashMap.end()) {
    throw std::invalid_argument("SecureRemotePassword log | calculateX(): "
                                "hash algorithm not recognized.");
  }
  if (username.empty() || password.empty() || saltHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateX(): "
        "invalid input parameters received, cannot be empty.");
  }
  // Step 1: Inner hash = H(username | ":" | password)
  const std::string inner{username + ":" + password};
  const std::string innerHashHex{_hashMap.at(hashName)(inner)};
  // Step 2: Convert saltHex and innerHashHex to raw bytes
  std::vector<uint8_t> saltBytes =
      MessageExtractionFacility::hexToBytes(saltHex);
  std::vector<uint8_t> innerHashBytes =
      MessageExtractionFacility::hexToBytes(innerHashHex);
  // Step 3: Concatenate saltBytes + innerHashBytes
  std::string concat(reinterpret_cast<const char *>(saltBytes.data()),
                     saltBytes.size());
  concat += std::string(reinterpret_cast<const char *>(innerHashBytes.data()),
                        innerHashBytes.size());
  // Step 4: Outer hash = H(salt | H(username | ":" | password))
  std::string xHex{_hashMap.at(hashName)(concat)};
  // Step 5: Return as uppercase hex
  std::transform(xHex.begin(), xHex.end(), xHex.begin(), ::toupper);
  return xHex;
}
/******************************************************************************/
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
 * @param NHex The hexadecimal representation of the SRP modulus N.
 * @return The session key S as a hexadecimal string.
 * @throw std::runtime_error if any of the calculations fail.
 */
std::string MyCryptoLibrary::SecureRemotePassword::calculateSClient(
    const std::string &BHex, const std::string &kHex, unsigned int g,
    const std::string &xHex, const std::string &aHex, const std::string &uHex,
    const std::string &NHex) {
  // Debugging information
  std::cout << "[DEBUG] calculateSClient input parameters:" << std::endl;
  std::cout << "  [DEBUG] BHex: " << BHex << std::endl;
  std::cout << "  [DEBUG] kHex: " << kHex << std::endl;
  std::cout << "  [DEBUG] g: " << g << std::endl;
  std::cout << "  [DEBUG] xHex: " << xHex << std::endl;
  std::cout << "  [DEBUG] aHex: " << aHex << std::endl;
  std::cout << "  [DEBUG] uHex: " << uHex << std::endl;
  std::cout << "  [DEBUG] NHex: " << NHex << std::endl;

  // Parameter validation
  if (BHex.empty() || kHex.empty() || xHex.empty() || aHex.empty() ||
      uHex.empty() || NHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateSClient(): One or more input "
        "parameters are empty.");
  } else if (g <= 1) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateSClient(): Generator g less or "
        "equal to 1.");
  }
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "Failed to allocate BN_CTX.");
  }
  BIGNUM *B{BN_new()}, *k{BN_new()}, *gx{BN_new()}, *x{BN_new()};
  BIGNUM *a{BN_new()}, *u{BN_new()}, *N{BN_new()};
  BIGNUM *tmp1{BN_new()}, *tmp2{BN_new()}, *S{BN_new()};
  if (!B || !k || !gx || !x || !a || !u || !N || !tmp1 || !tmp2 || !S) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "BIGNUM allocation failed");
  }
  BN_hex2bn(&B, BHex.c_str());
  BN_hex2bn(&k, kHex.c_str());
  BN_set_word(gx, g);
  BN_hex2bn(&x, xHex.c_str());
  BN_hex2bn(&a, aHex.c_str());
  BN_hex2bn(&u, uHex.c_str());
  BN_hex2bn(&N, NHex.c_str());
  // Compute g^x mod N
  if (!BN_mod_exp(gx, gx, x, N, ctx)) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "BN_mod_exp(g^x) failed");
  }
  // Compute k * g^x mod N
  if (!BN_mod_mul(tmp1, k, gx, N, ctx)) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "BN_mod_mul(k * g^x) failed");
  }
  // Compute (B - k * g^x) mod N
  if (!BN_mod_sub(tmp2, B, tmp1, N, ctx)) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "BN_mod_sub(B - k * g^x) failed");
  }
  // Compute (a + u * x)
  if (!BN_mul(tmp1, u, x, ctx)) {
    throw std::runtime_error(
        "SecureRemotePassword log | calculateSClient(): BN_mul(u * x) failed");
  }
  if (!BN_mod_add(tmp1, a, tmp1, N, ctx)) {
    throw std::runtime_error("SecureRemotePassword log | calculateSClient(): "
                             "BN_add(a + u * x) failed");
  }
  // Compute S = (B - k * g^x) ^ (a + u * x) mod N
  if (!BN_mod_exp(S, tmp2, tmp1, N, ctx)) {
    throw std::runtime_error(
        "SecureRemotePassword log | calculateSClient(): BN_mod_exp(S) failed");
  }
  // Convert S to hex string (uppercase)
  char *SHex{BN_bn2hex(S)};
  std::string SStr{SHex ? SHex : ""};
  OPENSSL_free(SHex);
  // Free resources
  BN_free(B);
  BN_free(k);
  BN_free(gx);
  BN_free(x);
  BN_free(a);
  BN_free(u);
  BN_free(N);
  BN_free(tmp1);
  BN_free(tmp2);
  BN_free(S);
  BN_CTX_free(ctx);
  // to upper case conversion
  std::transform(SStr.begin(), SStr.end(), SStr.begin(), ::toupper);
  return SStr;
}
/******************************************************************************/
/**
 * @brief Calculates the SRP shared secret S for the server side.
 *
 * Formula: S = (A * v^u) ^ b mod N
 *
 * @param AHex The hexadecimal representation of the client's public key A.
 * @param vHex The hexadecimal representation of the verifier v.
 * @param uHex The hexadecimal representation of the scrambling parameter u.
 * @param bHex The hexadecimal representation of the server's private key b.
 * @param NHex The hexadecimal representation of the modulus N.
 * @return The shared secret S as a hexadecimal string.
 * @throw std::runtime_error if any of the calculations fail.
 */
std::string MyCryptoLibrary::SecureRemotePassword::calculateSServer(
    const std::string &AHex, const std::string &vHex, const std::string &uHex,
    const std::string &bHex, const std::string &NHex) {
  // Debugging information
  std::cout << "[DEBUG] calculateSServer input parameters:" << std::endl;
  std::cout << "  [DEBUG] AHex: " << AHex << std::endl;
  std::cout << "  [DEBUG] vHex: " << vHex << std::endl;
  std::cout << "  [DEBUG] uHex: " << uHex << std::endl;
  std::cout << "  [DEBUG] bHex: " << bHex << std::endl;
  std::cout << "  [DEBUG] NHex: " << NHex << std::endl;

  // Parameter validation
  if (AHex.empty() || vHex.empty() || uHex.empty() || bHex.empty() ||
      NHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword log | calculateSServer(): One or more input "
        "parameters are empty.");
  }
  BN_CTX *ctx{BN_CTX_new()};
  if (!ctx) {
    throw std::runtime_error("SecureRemotePassword log | calculateSServer(): "
                             "Failed to allocate BN_CTX.");
  }
  BIGNUM *A{BN_new()}, *v{BN_new()}, *u{BN_new()}, *b{BN_new()}, *N{BN_new()};
  BIGNUM *vu{BN_new()}, *Avu{BN_new()}, *S{BN_new()};
  if (!A || !v || !u || !b || !N || !vu || !Avu || !S) {
    BN_CTX_free(ctx);
    BN_free(A);
    BN_free(v);
    BN_free(u);
    BN_free(b);
    BN_free(N);
    BN_free(vu);
    BN_free(Avu);
    BN_free(S);
    throw std::runtime_error("SecureRemotePassword log | calculateSServer(): "
                             "BIGNUM allocation failed");
  }
  BN_hex2bn(&A, AHex.c_str());
  BN_hex2bn(&v, vHex.c_str());
  BN_hex2bn(&u, uHex.c_str());
  BN_hex2bn(&b, bHex.c_str());
  BN_hex2bn(&N, NHex.c_str());
  // Compute v^u mod N
  if (!BN_mod_exp(vu, v, u, N, ctx)) {
    BN_CTX_free(ctx);
    BN_free(A);
    BN_free(v);
    BN_free(u);
    BN_free(b);
    BN_free(N);
    BN_free(vu);
    BN_free(Avu);
    BN_free(S);
    throw std::runtime_error("SecureRemotePassword log | calculateSServer(): "
                             "BN_mod_exp(v^u) failed");
  }
  // Compute A * v^u mod N
  if (!BN_mod_mul(Avu, A, vu, N, ctx)) {
    BN_CTX_free(ctx);
    BN_free(A);
    BN_free(v);
    BN_free(u);
    BN_free(b);
    BN_free(N);
    BN_free(vu);
    BN_free(Avu);
    BN_free(S);
    throw std::runtime_error("SecureRemotePassword log | calculateSServer(): "
                             "BN_mod_mul(A * v^u) failed");
  }
  // Compute S = (A * v^u) ^ b mod N
  if (!BN_mod_exp(S, Avu, b, N, ctx)) {
    BN_CTX_free(ctx);
    BN_free(A);
    BN_free(v);
    BN_free(u);
    BN_free(b);
    BN_free(N);
    BN_free(vu);
    BN_free(Avu);
    BN_free(S);
    throw std::runtime_error(
        "SecureRemotePassword log | calculateSServer(): BN_mod_exp(S) failed");
  }
  // Convert S to hex string (uppercase)
  char *SHex{BN_bn2hex(S)};
  std::string SStr{SHex ? SHex : ""};
  OPENSSL_free(SHex);
  BN_free(A);
  BN_free(v);
  BN_free(u);
  BN_free(b);
  BN_free(N);
  BN_free(vu);
  BN_free(Avu);
  BN_free(S);
  BN_CTX_free(ctx);
  std::transform(SStr.begin(), SStr.end(), SStr.begin(), ::toupper);
  return SStr;
}
/******************************************************************************/
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
std::string
MyCryptoLibrary::SecureRemotePassword::calculateK(const std::string &hash,
                                                  const std::string &SHex) {
  // Check hash algorithm exists
  if (_hashMap.find(hash) == _hashMap.end()) {
    throw std::invalid_argument("SecureRemotePassword log | calculateK(): "
                                "hash algorithm not recognized.");
  } else if (SHex.empty()) {
    throw std::invalid_argument("SecureRemotePassword log | calculateK(): "
                                "SHex in empty.");
  }
  // Convert S from hex string to bytes
  std::vector<uint8_t> SBytes{MessageExtractionFacility::hexToBytes(SHex)};
  // Convert bytes to string for hashing
  std::string SPlaintext(reinterpret_cast<const char *>(SBytes.data()),
                         SBytes.size());
  // Hash the byte string
  std::string KHex{_hashMap.at(hash)(SPlaintext)};
  // Return as uppercase hex
  std::transform(KHex.begin(), KHex.end(), KHex.begin(), ::toupper);
  return KHex;
}
/******************************************************************************/
/**
 * @brief This method calculates the SRP M value (message authentication code)
 * for the client.
 *
 * Formula: H(H(N) XOR H(g) | H(U) | s | A | B | K)
 * Clarification:
 * - H: hash algorithm;
 * - N: modulus;
 * - g: generator;
 * - U: username;
 * - s: salt;
 * - A: client's public key;
 * - B: server's public key;
 * - K: session key;
 *
 * @param hashName The hash algorithm to use (e.g., "SHA-256").
 * @param NHex The hexadecimal representation of the modulus N.
 * @param gHex The hexadecimal representation of the generator g.
 * @param username The username.
 * @param saltHex The hexadecimal representation of the salt.
 * @param AHex The hexadecimal representation of the client's public key A.
 * @param BHex The hexadecimal representation of the server's public key B.
 * @param KHex The hexadecimal representation of the SRP multiplier parameter k.
 * @return The computed M value as a hexadecimal string.
 * @throw std::runtime_error if any of the calculations fail.
 */
std::string MyCryptoLibrary::SecureRemotePassword::calculateM(
    const std::string &hashName, const std::string &NHex,
    const std::string &gHex, const std::string &username,
    const std::string &saltHex, const std::string &AHex,
    const std::string &BHex, const std::string &KHex) {
  if (hashName.empty() || NHex.empty() || gHex.empty() || username.empty() ||
      saltHex.empty() || AHex.empty() || BHex.empty() || KHex.empty()) {
    throw std::invalid_argument("SecureRemotePassword log | calculateM(): "
                                "empty input parameters received.");
  }
  // Check hash algorithm exists
  if (_hashMap.find(hashName) == _hashMap.end()) {
    throw std::invalid_argument("SecureRemotePassword log | calculateM(): "
                                "hash algorithm not recognized.");
  }
  EncryptionUtility::HashFn hashFn{_hashMap.at(hashName)};
  // H(N)
  std::vector<uint8_t> NBytes{MessageExtractionFacility::hexToBytes(NHex)};
  const std::string NPlain(reinterpret_cast<const char *>(NBytes.data()),
                           NBytes.size());
  const std::string hashN{hashFn(NPlain)};
  // H(g)
  std::vector<uint8_t> gBytes{MessageExtractionFacility::hexToBytes(gHex)};
  const std::string gPlain(reinterpret_cast<const char *>(gBytes.data()),
                           gBytes.size());
  const std::string hashG{hashFn(gPlain)};
  // H(U)
  std::string hashU{hashFn(username)};
  std::vector<uint8_t> hashUBytes{MessageExtractionFacility::hexToBytes(hashU)};
  const std::string hashUPlain(
      reinterpret_cast<const char *>(hashUBytes.data()), hashUBytes.size());
  // H(N) XOR H(g)
  if (hashN.size() != hashG.size()) {
    throw std::runtime_error("SecureRemotePassword log | calculateM(): "
                             "H(N) and H(g) length mismatch.");
  }
  std::vector<uint8_t> hashNBytes{MessageExtractionFacility::hexToBytes(hashN)};
  std::vector<uint8_t> hashGBytes{MessageExtractionFacility::hexToBytes(hashG)};
  std::string hashN_xor_hashG(hashNBytes.size(), '\0');
  for (size_t i = 0; i < hashNBytes.size(); ++i) {
    hashN_xor_hashG[i] = hashNBytes[i] ^ hashGBytes[i];
  }
  // Prepare salt, A, B, K as bytes
  std::vector<uint8_t> saltBytes{
      MessageExtractionFacility::hexToBytes(saltHex)};
  const std::string saltPlain(reinterpret_cast<const char *>(saltBytes.data()),
                              saltBytes.size());
  std::vector<uint8_t> ABytes{MessageExtractionFacility::hexToBytes(AHex)};
  const std::string APlain(reinterpret_cast<const char *>(ABytes.data()),
                           ABytes.size());
  std::vector<uint8_t> BBytes{MessageExtractionFacility::hexToBytes(BHex)};
  const std::string BPlain(reinterpret_cast<const char *>(BBytes.data()),
                           BBytes.size());
  std::vector<uint8_t> KBytes{MessageExtractionFacility::hexToBytes(KHex)};
  const std::string KPlain(reinterpret_cast<const char *>(KBytes.data()),
                           KBytes.size());
  // Concatenate all parts
  const std::string MInput{hashN_xor_hashG + hashUPlain + saltPlain + APlain +
                           BPlain + KPlain};
  // Hash the concatenated value
  std::string MHex{hashFn(MInput)};
  // Return as uppercase hex
  std::transform(MHex.begin(), MHex.end(), MHex.begin(), ::toupper);
  return MHex;
}
/******************************************************************************/
