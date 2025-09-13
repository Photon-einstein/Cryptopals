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
    _kMap[groupId] =
        EncryptionUtility::calculateK(params._nHex, gHex, params._hashName);
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
                 "not in "
                 "valid range (1 < key < N)."
              << std::endl;
    return false;
  }
  return true;
}
/******************************************************************************/
