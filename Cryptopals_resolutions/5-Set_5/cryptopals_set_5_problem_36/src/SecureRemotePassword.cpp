#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

#include "./../include/EncryptionUtility.hpp"
#include "./../include/SecureRemotePassword.hpp"

/* static fields initialization */
unsigned int MyCryptoLibrary::SecureRemotePassword::_minSizePrivateKey = 256;

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
    : _debugFlag{debugFlag} {
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
  if (debugFlag) {
    std::cout << std::endl;
  }
  for (const std::pair<const unsigned int, SrpParametersLoader::SrpParameters>
           &entry : _srpParametersMap) {
    const unsigned int groupId = entry.first;
    const SrpParametersLoader::SrpParameters &params = entry.second;
    const std::string gHex = MessageExtractionFacility::uintToHex(params._g);
    _kMap[groupId] = calculateK(params._nHex, gHex, params._hashName);
    if (_debugFlag) {
      std::cout << "k[group ID = " << groupId << "] = "
                << MessageExtractionFacility::BIGNUMToHex(_kMap[groupId].get())
                << std::endl;
    }
  }
  if (debugFlag) {
    std::cout << std::endl;
  }
}
/******************************************************************************/
MyCryptoLibrary::SecureRemotePassword::~SecureRemotePassword() {}
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
    throw std::runtime_error("Secure Remote Password log | "
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
MyCryptoLibrary::SecureRemotePassword::getKMap() const {
  if (_kMap.empty()) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getKMap(): dictionary not initialized");
  }
  return _kMap;
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
 * @param nHex N in hexadecimal format.
 * @param minSizeBits The minimum amount of bits that the private key should
 * have.
 *
 * @return The private key in a string, in hexadecimal format.
 */
std::string MyCryptoLibrary::SecureRemotePassword::generatePrivateKey(
    const std::string &nHex, const unsigned int minSizeBits) {
  // Convert N from hex to BIGNUM
  MessageExtractionFacility::UniqueBIGNUM nBn =
      MessageExtractionFacility::hexToUniqueBIGNUM(nHex);
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
  int nBits = BN_num_bits(nBn.get());
  if (minSizeBits > nBits) {
    throw std::runtime_error(
        "SecureRemotePassword log | generatePrivateKey(): minSizeBits greater "
        "than the number of bits of N");
  }
  int bits = std::max(static_cast<int>(minSizeBits), nBits);
  // Generate random private key: 1 <= privateKey < N, at least minSizeBits bits
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
 * @param nHex The group prime N in hexadecimal format.
 * @param gHex The generator g in hexadecimal format.
 * @param isServer If true, computes B (server); if false, computes A
 * (client).
 * @param k Optional: the SRP multiplier parameter as BIGNUM (required for B).
 * @param vHex Optional: the verifier v in hex (required for B).
 * @return The public key (A or B) as a hexadecimal string.
 * @throws std::runtime_error if constraints are not met.
 */
std::string MyCryptoLibrary::SecureRemotePassword::calculatePublicKey(
    const std::string &privateKeyHex, const std::string &nHex,
    const std::string &gHex, bool isServer, const BIGNUM *k,
    const std::string &vHex) {
  // Convert inputs to BIGNUMs
  MessageExtractionFacility::UniqueBIGNUM n =
      MessageExtractionFacility::hexToUniqueBIGNUM(nHex);
  MessageExtractionFacility::UniqueBIGNUM g =
      MessageExtractionFacility::hexToUniqueBIGNUM(gHex);
  MessageExtractionFacility::UniqueBIGNUM privateKey =
      MessageExtractionFacility::hexToUniqueBIGNUM(privateKeyHex);
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
    MessageExtractionFacility::UniqueBIGNUM v =
        MessageExtractionFacility::hexToUniqueBIGNUM(vHex);
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
    throw std::runtime_error(
        "Secure Remote Password log | calculatePublicKey(): Public key not in "
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
 * @param nHex The group prime N in hexadecimal format.
 * @return True if the validation passes, false otherwise.
 */
bool MyCryptoLibrary::SecureRemotePassword::validatePublicKey(
    const std::string &publicKeyHex, const std::string &nHex) {
  // input parameter validation
  if (publicKeyHex.empty() || nHex.empty()) {
    std::cerr << "Secure Remote Password log | validatePublicKey(): parameters "
                 "received are empty."
              << std::endl;
    return false;
  }
  // Convert inputs to BIGNUMs
  MessageExtractionFacility::UniqueBIGNUM publicKey =
      MessageExtractionFacility::hexToUniqueBIGNUM(publicKeyHex);
  MessageExtractionFacility::UniqueBIGNUM n =
      MessageExtractionFacility::hexToUniqueBIGNUM(nHex);
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
 * where H is the agreed hash function, N is the group prime (as a hex string),
 * and PAD(g) is the generator g left-padded with zeros to the length of N.
 * The result is returned as a UniqueBIGNUM.
 *
 * @param nHex The group prime N in hexadecimal format.
 * @param gHex The generator g in hexadecimal format.
 * @param hashName The name of the hash function to use (e.g., "SHA-256").
 * @return The computed k parameter as a UniqueBIGNUM.
 * @throws std::invalid_argument if N or g is empty, or if g >= N.
 * @throws std::runtime_error if conversion or hashing fails.
 */
MessageExtractionFacility::UniqueBIGNUM
MyCryptoLibrary::SecureRemotePassword::calculateK(const std::string &nHex,
                                                  const std::string &gHex,
                                                  const std::string &hashName) {
  // input parameters validation
  if (nHex.empty() || gHex.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): N or g is empty.");
  }
  // 1. Convert N and g to bytes and validate parameters one more time
  std::vector<uint8_t> nBytes = MessageExtractionFacility::hexToBytes(nHex);
  std::vector<uint8_t> gBytes = MessageExtractionFacility::hexToBytes(gHex);
  if (nBytes.empty() ||
      nBytes.size() < 16) { // 16 bytes / 128 bits minimum for safety
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): N is too small or invalid.");
  } else if (gBytes.empty()) {
    throw std::invalid_argument(
        "SecureRemotePassword::calculateK(): g is invalid.");
  }
  BIGNUM *nBn = BN_bin2bn(nBytes.data(), nBytes.size(), nullptr);
  BIGNUM *gBn = BN_bin2bn(gBytes.data(), gBytes.size(), nullptr);
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
  std::vector<uint8_t> gPadded =
      EncryptionUtility::padLeft(gBytes, nBytes.size());
  // 3. Concatenate N || PAD(g)
  std::vector<uint8_t> inputBytes(nBytes);
  inputBytes.insert(inputBytes.end(), gPadded.begin(), gPadded.end());
  // 5. Hash
  const auto &hashMap = EncryptionUtility::getHashMap();
  auto it = hashMap.find(hashName);
  if (it == hashMap.end()) {
    throw std::runtime_error(
        "SecureRemotePassword::calculateK(): Unsupported hash");
  }
  std::string hashHex = it->second(std::string(
      reinterpret_cast<const char *>(inputBytes.data()), inputBytes.size()));
  // 6. Convert Hex to BigNum
  return MessageExtractionFacility::hexToUniqueBIGNUM(hashHex);
}
/******************************************************************************/
/**
 * @brief This method calculates the value of U for the SRP protocol.
 *
 * @param hashName The name of the hash function to use (e.g., "SHA-256").
 * @param aHex The client's public key A in hexadecimal format.
 * @param bHex The server's public key B in hexadecimal format.
 * @return The calculated value of U as a hexadecimal string.
 * @throws std::runtime_error if an error occurs during calculation.
 */
std::string
MyCryptoLibrary::SecureRemotePassword::calculateU(const std::string &hashName,
                                                  const std::string &AHex,
                                                  const std::string &BHex) {
  // Convert A and B from hex to bytes
  std::vector<uint8_t> ABytes = MessageExtractionFacility::hexToBytes(AHex);
  std::vector<uint8_t> BBytes = MessageExtractionFacility::hexToBytes(BHex);
  // Concatenate A || B
  std::vector<uint8_t> inputBytes(ABytes);
  inputBytes.insert(inputBytes.end(), BBytes.begin(), BBytes.end());
  const auto &hashMap = EncryptionUtility::getHashMap();
  auto it = hashMap.find(hashName);
  if (it == hashMap.end()) {
    throw std::runtime_error(
        "SecureRemotePassword::calculateU(): Unsupported hash");
  }
  std::string hashHex = it->second(std::string(
      reinterpret_cast<const char *>(inputBytes.data()), inputBytes.size()));
  // Convert hashHex to uppercase (if not already)
  // std::transform(hashHex.begin(), hashHex.end(), hashHex.begin(), ::toupper);
  return hashHex;
}
/******************************************************************************/
