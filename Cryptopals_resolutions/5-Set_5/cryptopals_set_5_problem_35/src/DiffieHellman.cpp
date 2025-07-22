#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

#include "./../include/DiffieHellman.hpp"

/* constructor / destructor */

/**
 * @brief This method will execute the constructor of the DiffieHellman object.
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
MyCryptoLibrary::DiffieHellman::DiffieHellman(const bool debugFlag,
                                              const std::string &groupName)
    : _privateKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _publicKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _sharedSecret{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _debugFlag{debugFlag}, _groupName{groupName} {
  if (_groupName.size() == 0) {
    throw std::runtime_error("Diffie Hellman log | constructor(): "
                             "Group name is null");
  }
  std::map<std::string, DhParametersLoader::DhParameters> dhParametersMap =
      DhParametersLoader::loadDhParameters(getDhParametersFilenameLocation());
  if (dhParametersMap.find(groupName) != dhParametersMap.end()) {
    _dhParameter = dhParametersMap[groupName];
    _p = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter._pHex);
    _g = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter._gHex);
    if (_debugFlag) {
      std::cout << "Diffie Hellman log | p (decimal) = "
                << MessageExtractionFacility::BIGNUMToDec(_p.get())
                << std::endl;
      std::cout << "Diffie Hellman log | g (decimal) = "
                << MessageExtractionFacility::BIGNUMToDec(_g.get())
                << std::endl;
    }
    generatePrivateKey();
    generatePublicKey();
  } else {
    throw std::runtime_error("Diffie Hellman log | constructor(): "
                             "Group name is invalid");
  }
}
/******************************************************************************/
/**
 * @brief This method will execute the constructor of the DiffieHellman object.
 *
 * This method will execute the constructor of the DiffieHellman object when the
 * input parameters 'p' and 'g' are given.
 *
 * @param debugFlag The boolean flag to decide if aggressive prints should be
 * displayed into the standard output, created for troubleshooting purposes.
 * @param p The prime p to be used in the Diffie Hellman key exchange protocol.
 * @param g The generator g to be used in the Diffie Hellman key exchange
 * protocol.
 *
 * @throw runtime_error if the prime p or generator g are null.
 */
MyCryptoLibrary::DiffieHellman::DiffieHellman(const bool debugFlag,
                                              const std::string &p,
                                              const std::string &g)
    : _privateKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _publicKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _sharedSecret{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _debugFlag{debugFlag} {
  if (p.size() == 0) {
    throw std::runtime_error("Diffie Hellman log | constructor(): "
                             "Prime p is null");
  } else if (g.size() == 0) {
    throw std::runtime_error("Diffie Hellman log | constructor(): "
                             "Generator g is null");
  }
  std::map<std::string, DhParametersLoader::DhParameters> dhParametersMap =
      DhParametersLoader::loadDhParameters(getDhParametersFilenameLocation());
  _p = MessageExtractionFacility::hexToUniqueBIGNUM(p);
  _g = MessageExtractionFacility::hexToUniqueBIGNUM(g);
  if (_debugFlag) {
    std::cout << "Diffie Hellman log | p (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_p.get()) << std::endl;
    std::cout << "Diffie Hellman log | g (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_g.get()) << std::endl;
  }
  generatePrivateKey();
  generatePublicKey();
}
/******************************************************************************/
/**
 * @brief This method will perform the destruction of the DiffieHellman object.
 *
 * This method will perform the destruction of the DiffieHellman object,
 * releasing all the resources and memory used.
 */
MyCryptoLibrary::DiffieHellman::~DiffieHellman() {}
/******************************************************************************/
/**
 * @brief This method will return the public key.
 *
 * This method will return the public key used at the Diffie Hellman
 * key exchange protocol.
 *
 * @return The public key (hex) in a string format.
 */
const std::string MyCryptoLibrary::DiffieHellman::getPublicKey() const {
  return MessageExtractionFacility::BIGNUMToHex(_publicKey.get());
}
/******************************************************************************/
/**
 * @brief This method will return the group name.
 *
 * This method will return the group name used at the Diffie Hellman
 * key exchange protocol.
 *
 * @return The group name in a string format.
 */
const std::string &MyCryptoLibrary::DiffieHellman::getGroupName() const {
  return _dhParameter._groupName;
}
/******************************************************************************/
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
const std::string MyCryptoLibrary::DiffieHellman::deriveSharedSecret(
    const std::string &peerPublicKeyHex, const std::string &serverNonceHex,
    const std::string &clientNonceHex) {
  if (!_privateKey || BN_is_zero(_privateKey.get())) {
    throw std::runtime_error("Diffie Hellman log | deriveSharedSecret(): "
                             "Private key has not been generated for the "
                             "derivation of the shared secret");
  }
  if (!_g || BN_is_zero(_g.get())) {
    throw std::runtime_error("Diffie Hellman log | deriveSharedSecret(): "
                             "Generator 'g' is not initialized for the "
                             "derivation of the shared secret");
  }
  if (!_p || BN_is_zero(_p.get())) {
    throw std::runtime_error("Diffie Hellman log | deriveSharedSecret(): "
                             "Modulus 'p' is not initialized for the "
                             "derivation of the shared secret");
  }
  MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
      MessageExtractionFacility::hexToUniqueBIGNUM(peerPublicKeyHex);
  if (!peerPublicKey) {
    throw std::runtime_error("Diffie Hellman log | deriveSharedSecret(): "
                             "peerPublicKey is not initialized for the "
                             "derivation of the shared secret");
  }
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    throw std::runtime_error(
        "Diffie Hellman log | deriveSharedSecret(): Failed to create BIGNUM "
        "context for public key calculation.");
  }
  // Compute _sharedSecret = (peerPublicKey ^ _privateKey) % _p
  // BN_mod_exp(result, base, exponent, modulus, context)
  if (!BN_mod_exp(_sharedSecret.get(), peerPublicKey.get(), _privateKey.get(),
                  _p.get(), ctx)) {
    // Handle error from OpenSSL
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    BN_CTX_free(ctx); // Free context on error
    throw std::runtime_error("Diffie Hellman log | deriveSharedSecret(): "
                             "Failed to calculate shared "
                             "secret (BN_mod_exp): " +
                             std::string(errorBuffer));
  }
  BN_CTX_free(ctx);
  const std::string sharedSecretHex{
      MessageExtractionFacility::BIGNUMToHex(_sharedSecret.get())};
  if (_debugFlag) {
    std::cout << "\nDiffie Hellman log | Generated shared secret (hex): "
              << sharedSecretHex << std::endl;
    std::cout << "Diffie Hellman log | Generated shared secret (dec): "
              << MessageExtractionFacility::BIGNUMToDec(_sharedSecret.get())
              << std::endl;
    std::cout << "Diffie Hellman log | Generated shared secret bit length: "
              << BN_num_bits(_sharedSecret.get()) << "\n"
              << std::endl;
  }
  // --- KDF Step: Incorporate nonces into the key material derivation ---
  // 1. Convert the raw BIGNUM shared secret to a byte array
  int numBytes = BN_num_bytes(_sharedSecret.get());
  std::vector<unsigned char> sharedSecretRawBytes(numBytes);
  if (BN_bn2bin(_sharedSecret.get(), sharedSecretRawBytes.data()) != numBytes) {
    throw std::runtime_error(
        "Diffie Hellman log | deriveSharedSecret(): Failed to convert shared "
        "secret BIGNUM to bytes.");
  }
  // 2. Decode nonce hex strings to byte vectors
  std::vector<unsigned char> serverNonceBytes =
      MessageExtractionFacility::hexToBytes(serverNonceHex);
  std::vector<unsigned char> clientNonceBytes =
      MessageExtractionFacility::hexToBytes(clientNonceHex);
  // 3. Concatenate shared_secret_raw_bytes || clientNonceBytes ||
  // serverNonceBytes
  std::vector<unsigned char> dataToHash;
  dataToHash.reserve(sharedSecretRawBytes.size() + clientNonceBytes.size() +
                     serverNonceBytes.size());
  dataToHash.insert(dataToHash.end(), sharedSecretRawBytes.begin(),
                    sharedSecretRawBytes.end());
  dataToHash.insert(dataToHash.end(), clientNonceBytes.begin(),
                    clientNonceBytes.end());
  dataToHash.insert(dataToHash.end(), serverNonceBytes.begin(),
                    serverNonceBytes.end());
  // 4. Hash the concatenated data
  std::vector<uint8_t> keyMaterial(
      SHA256_DIGEST_LENGTH); // SHA256_DIGEST_LENGTH is 32 bytes
  SHA256(dataToHash.data(), dataToHash.size(), keyMaterial.data());
  if (_debugFlag) {
    std::cout << "\nDiffie Hellman log | Derived raw shared secret (hex): "
              << sharedSecretHex << std::endl;
    std::cout << "Diffie Hellman log | Client Nonce (hex): " << clientNonceHex
              << std::endl;
    std::cout << "Diffie Hellman log | Server Nonce (hex): " << serverNonceHex
              << std::endl;
    std::cout << "Diffie Hellman log | Derived key material (SHA256 hex): "
              << MessageExtractionFacility::toHexString(keyMaterial)
              << std::endl;
  }
  _derivedSymmetricKey.clear();
  _derivedSymmetricKey = keyMaterial;
  _derivedSymmetricKeyHex = MessageExtractionFacility::toHexString(keyMaterial);
  return _derivedSymmetricKeyHex;
}
/******************************************************************************/
/**
 * @brief This method returns the symmetric key after the Diffie
 * Hellman key exchange protocol has been completed.
 *
 * @return The symmetric key.
 * @throws std::runtime_error if the Diffie Hellman key exchange protocol
 * has failed.
 */
const std::vector<uint8_t> &
MyCryptoLibrary::DiffieHellman::getSymmetricKey() const {
  const int keyLength = EVP_CIPHER_key_length(EVP_aes_256_cbc());
  if (_derivedSymmetricKey.size() != keyLength) {
    throw std::runtime_error(
        "Diffie Hellman log | getSymmetricKey(): Diffie Hellman key exchange "
        "protocol must be completed before retrieving the derived symmetric "
        "key.");
  }
  return _derivedSymmetricKey;
}
/******************************************************************************/
/**
 * @brief This method returns the expected confirmation message of a successful
 * Diffie Hellman key exchange.
 *
 * @return Expected confirmation message of a successful Diffie Hellman's key
 * exchange.
 * @throws std::runtime_error if the confirmation message is empty.
 */
const std::string &
MyCryptoLibrary::DiffieHellman::getConfirmationMessage() const {
  if (_confirmationMessage.empty()) {
    throw std::runtime_error("Diffie Hellman log | getConfirmationMessage(): "
                             "confirmation message is empty.");
  }
  return _confirmationMessage;
}
/******************************************************************************/
/**
 * @brief This method returns the location of the file where the public
 * configurations of the Diffie Hellman key exchange protocol are available.
 *
 * @return The filename where the public configurations of the Diffie Hellman
 * key exchange protocol are available.
 * @throws std::runtime_error if the DH parameters filename is empty.
 */
const std::string &
MyCryptoLibrary::DiffieHellman::getDhParametersFilenameLocation() const {
  if (_dhParametersFilename.size() == 0) {
    throw std::runtime_error(
        "Diffie Hellman log | getDhParametersFilenameLocation(): public DH "
        "parameters filename location is empty.");
  }
  return _dhParametersFilename;
}

/**
 * @brief This method returns the prime p used in the Diffie Hellman key
 * exchange protocol.
 *
 * @return The prime p, in hexadecimal format.
 * @throws std::runtime_error if the prime p is not set.
 */
const std::string MyCryptoLibrary::DiffieHellman::getPrimeP() const {
  if (!_p) {
    throw std::runtime_error("Diffie Hellman log | getPrimeP(): "
                             "prime p is not set.");
  }
  return MessageExtractionFacility::BIGNUMToHex(_p.get());
}
/******************************************************************************/
/**
 * @brief This method returns the generator g used in the Diffie Hellman key
 * exchange protocol.
 *
 * @return The generator g, in hexadecimal format.
 * @throws std::runtime_error if the generator g is not set.
 */
const std::string MyCryptoLibrary::DiffieHellman::getGeneratorG() const {
  if (!_g) {
    throw std::runtime_error("Diffie Hellman log | getGeneratorG(): "
                             "generator g is not set.");
  }
  return MessageExtractionFacility::BIGNUMToHex(_g.get());
};
/******************************************************************************/
/**
 * @brief This method will set the value of the prime p.
 *
 * @param pHex The prime p in hexadecimal format.
 *
 * @throws std::runtime_error if the prime p is empty.
 */
void MyCryptoLibrary::DiffieHellman::setPrimeP(const std::string &pHex) {
  if (pHex.empty()) {
    throw std::runtime_error("Diffie Hellman log | setPrimeP(): "
                             "input pHex is empty.");
  }
  _p = MessageExtractionFacility::hexToUniqueBIGNUM(pHex);
}
/******************************************************************************/
/**
 * @brief This method will set the value of the generator g.
 *
 * @param gHex The generator g in hexadecimal format.
 *
 * @throws std::runtime_error if the generator g is empty.
 */
void MyCryptoLibrary::DiffieHellman::setGeneratorG(const std::string &gHex) {
  if (gHex.empty()) {
    throw std::runtime_error("Diffie Hellman log | setGeneratorG(): "
                             "input gHex is empty.");
  }
  _g = MessageExtractionFacility::hexToUniqueBIGNUM(gHex);
}
/******************************************************************************/
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
bool MyCryptoLibrary::DiffieHellman::testValueRawSharedSecret(
    const std::string &sharedSecretRawGuessHex) {
  const std::string sharedSecretRawHex =
      MessageExtractionFacility::BIGNUMToHex(_sharedSecret.get());
  return sharedSecretRawHex == sharedSecretRawGuessHex;
}
/******************************************************************************/
/**
 * @brief This method will generate a private key.
 *
 * This method will generate a private key to be used at a Diffie
 * Hellman key exchange protocol.
 *
 * @throws std::runtime_error if there is an error in the generation of the
 * private key.
 */
void MyCryptoLibrary::DiffieHellman::generatePrivateKey() {
  // The private key 'a' must be 1 < a < p-1.
  // So, we need to generate a random number 'x' such that 0 <= x < (p-2).
  // Then, set 'a = x + 2'. This ensures 'a' is in the range [2, p-1).
  MessageExtractionFacility::UniqueBIGNUM rangeForRand =
      MessageExtractionFacility::UniqueBIGNUM(BN_dup(_p.get()));
  // Subtract: p(copy) - 2
  if (!BN_sub_word(rangeForRand.get(), 2)) {
    // BN_sub_word returns 0 if subtraction causes negative result or fails
    // For large primes, this should not happen if p > 2.
    throw std::runtime_error(
        "Diffie Hellman log | generatePrivateKey(): BN_sub_word failed for "
        "random range calculation.");
  }
  if (BN_is_zero(rangeForRand.get()) || BN_is_negative(rangeForRand.get())) {
    throw std::invalid_argument("Diffie Hellman log | generatePrivateKey(): "
                                "Modulus p is too small for generating a valid "
                                "private key range (p must be > 2).");
  }
  // Generate random number 'x' such that 0 <= x < (p-2)
  // BN_rand_range(rnd, range) generates 0 <= rnd < range
  if (!BN_rand_range(_privateKey.get(), rangeForRand.get())) {
    // BN_rand_range returns 0 on error
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    throw std::runtime_error("Diffie Hellman log | generatePrivateKey(): "
                             "Failed to generate random private key: " +
                             std::string(errorBuffer));
  }
  // Add 2 to 'x' to get 'a' in the range [2, p-1)
  if (!BN_add_word(_privateKey.get(), 2)) {
    // BN_add_word returns 0 on error
    throw std::runtime_error("Diffie Hellman log | generatePrivateKey(): "
                             "Failed to adjust private key to range [2, p-1).");
  }
  if (_debugFlag) {
    std::cout << "\nDiffie Hellman log | Generated private key (hex): "
              << MessageExtractionFacility::BIGNUMToHex(_privateKey.get())
              << std::endl;
    std::cout << "Diffie Hellman log | Generated private key (dec): "
              << MessageExtractionFacility::BIGNUMToDec(_privateKey.get())
              << std::endl;
    std::cout << "Diffie Hellman log | Private key bit length: "
              << BN_num_bits(_privateKey.get()) << std::endl;
  }
}
/******************************************************************************/
/**
 * @brief This method will generate a public key.
 *
 * This method will generate a public key to be used at a Diffie
 * Hellman key exchange protocol. A = g^a mod p
 *
 * @throws std::runtime_error if there is an error in the generation of
 * the public key.
 */
void MyCryptoLibrary::DiffieHellman::generatePublicKey() {
  if (!_privateKey || BN_is_zero(_privateKey.get())) {
    throw std::runtime_error(
        "Diffie Hellman log | generatePublicKey(): Private key has not been "
        "generated. Call generatePrivateKey() first.");
  }
  if (!_g || BN_is_zero(_g.get())) {
    throw std::runtime_error("Diffie Hellman log | generatePublicKey(): "
                             "Generator 'g' is not initialized.");
  }
  if (!_p || BN_is_zero(_p.get())) {
    throw std::runtime_error("Diffie Hellman log | generatePublicKey(): "
                             "Modulus 'p' is not initialized.");
  }
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    throw std::runtime_error(
        "Diffie Hellman log | generatePublicKey(): Failed to create BIGNUM "
        "context for public key calculation.");
  }
  // Compute _publicKey = (_g ^ _privateKey) % _p
  // BN_mod_exp(result, base, exponent, modulus, context)
  if (!BN_mod_exp(_publicKey.get(), _g.get(), _privateKey.get(), _p.get(),
                  ctx)) {
    // Handle error from OpenSSL
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    BN_CTX_free(ctx); // Free context on error
    throw std::runtime_error("Diffie Hellman log | generatePublicKey(): "
                             "Failed to calculate public key (BN_mod_exp): " +
                             std::string(errorBuffer));
  }
  BN_CTX_free(ctx);
  if (_debugFlag) {
    std::cout << "\nDiffie Hellman log | Generated public key (hex): "
              << MessageExtractionFacility::BIGNUMToHex(_publicKey.get())
              << std::endl;
    std::cout << "Diffie Hellman log | Generated public key (dec): "
              << MessageExtractionFacility::BIGNUMToDec(_publicKey.get())
              << std::endl;
    std::cout << "Diffie Hellman log | Public key bit length: "
              << BN_num_bits(_publicKey.get()) << "\n"
              << std::endl;
  }
}
/******************************************************************************/
/**
 * @brief This method will test if the guess of the shared secret match the
 * the real value, that is assumed to be p-1.
 *
 * This method will test if the guess of the shared secret match the
 * the real value of the raw shared secret.
 *
 * @return True if the values match, false otherwise.
 */
bool MyCryptoLibrary::DiffieHellman::
    testValueRawSharedSecretNegativeHypothesis() {
  // The hypothesis is that the actual secret is (p-1).
  if (!_sharedSecret || !_p) {
    // Handle error: BIGNUMs not initialized
    return false;
  }
  // 1. Create a BIGNUM for (p - 1)
  MessageExtractionFacility::UniqueBIGNUM pMinus1Bn{
      MessageExtractionFacility::UniqueBIGNUM(BN_new())};
  if (!pMinus1Bn) {
    // Handle error: allocation failed
    return false;
  }
  // Subtract 1 from p
  if (BN_sub(pMinus1Bn.get(), _p.get(), BN_value_one()) == 0) {
    // Handle error: BN_sub failed
    return false;
  }
  // 2. Compare the actual shared secret with (p - 1)
  // BN_cmp returns 0 if equal, > 0 if first is greater, < 0 if first is smaller
  return BN_cmp(_sharedSecret.get(), pMinus1Bn.get()) == 0;
}
/******************************************************************************/
