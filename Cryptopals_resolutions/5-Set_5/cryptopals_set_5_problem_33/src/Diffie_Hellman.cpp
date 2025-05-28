#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdexcept>

#include "./../include/Diffie_Hellman.hpp"

/* constructor / destructor */
MyCryptoLibrary::Diffie_Hellman::Diffie_Hellman()
    : _privateKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())},
      _publicKey{MessageExtractionFacility::UniqueBIGNUM(BN_new())} {
  std::map<std::string, DHParametersLoader::DHParameters> dhParametersMap =
      DHParametersLoader::loadDhParameters(_dhParametersFilename);
  if (dhParametersMap.find("cryptopals-group-33-small") !=
      dhParametersMap.end()) {
    _dhParameter = dhParametersMap["cryptopals-group-33-small"];
    _p = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter.pHex);
    _g = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter.gHex);
    std::cout << "p (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_p.get()) << std::endl;
    std::cout << "g (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_g.get()) << std::endl;
    generatePrivateKey();
    generatePublicKey();
  }
}
/******************************************************************************/
MyCryptoLibrary::Diffie_Hellman::~Diffie_Hellman() {}
/******************************************************************************/
const std::string MyCryptoLibrary::Diffie_Hellman::getPublicKey() {
  return MessageExtractionFacility::BIGNUMToHex(_publicKey.get());
}
/******************************************************************************/
const std::string MyCryptoLibrary::Diffie_Hellman::getGroupName() {
  return _dhParameter.groupName;
}
/******************************************************************************/
void MyCryptoLibrary::Diffie_Hellman::generatePrivateKey() {
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
        "BN_sub_word failed for random range calculation.");
  }
  if (BN_is_zero(rangeForRand.get()) || BN_is_negative(rangeForRand.get())) {
    throw std::invalid_argument("Modulus p is too small for generating a valid "
                                "private key range (p must be > 2).");
  }
  // Generate random number 'x' such that 0 <= x < (p-2)
  // BN_rand_range(rnd, range) generates 0 <= rnd < range
  if (!BN_rand_range(_privateKey.get(), rangeForRand.get())) {
    // BN_rand_range returns 0 on error
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    throw std::runtime_error("Failed to generate random private key: " +
                             std::string(errorBuffer));
  }
  // Add 2 to 'x' to get 'a' in the range [2, p-1)
  if (!BN_add_word(_privateKey.get(), 2)) {
    // BN_add_word returns 0 on error
    throw std::runtime_error("Failed to adjust private key to range [2, p-1).");
  }
  // --- Optional: For debugging/logging (remove in production) ---
  std::cout << "\nGenerated private key (hex): "
            << MessageExtractionFacility::BIGNUMToHex(_privateKey.get())
            << std::endl;
  std::cout << "Generated private key (dec): "
            << MessageExtractionFacility::BIGNUMToDec(_privateKey.get())
            << std::endl;
  std::cout << "Private key bit length: " << BN_num_bits(_privateKey.get())
            << std::endl;
  // }
  // ---------------------------------------------------------------
}
/******************************************************************************/
// New method to calculate the public key: A = g^a mod p
void MyCryptoLibrary::Diffie_Hellman::generatePublicKey() {
  if (!_privateKey || BN_is_zero(_privateKey.get())) {
    throw std::runtime_error(
        "Private key has not been generated. Call generatePrivateKey() first.");
  }
  if (!_g || BN_is_zero(_g.get())) {
    throw std::runtime_error("Generator 'g' is not initialized.");
  }
  if (!_p || BN_is_zero(_p.get())) {
    throw std::runtime_error("Modulus 'p' is not initialized.");
  }
  BN_CTX *ctx = BN_CTX_new();
  if (!ctx) {
    throw std::runtime_error(
        "Failed to create BIGNUM context for public key calculation.");
  }
  // Compute _publicKey = (_g ^ _privateKey) % _p
  // BN_mod_exp(result, base, exponent, modulus, context)
  if (!BN_mod_exp(_publicKey.get(), _g.get(), _privateKey.get(), _p.get(),
                  ctx)) {
    // Handle error from OpenSSL
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    BN_CTX_free(ctx); // Free context on error
    throw std::runtime_error("Failed to calculate public key (BN_mod_exp): " +
                             std::string(errorBuffer));
  }

  BN_CTX_free(ctx);
  // --- Optional: For debugging/logging (remove in production) ---
  std::cout << "\nGenerated public key (hex): "
            << MessageExtractionFacility::BIGNUMToHex(_publicKey.get())
            << std::endl;
  std::cout << "Generated public key (dec): "
            << MessageExtractionFacility::BIGNUMToDec(_publicKey.get())
            << std::endl;
  std::cout << "Public key bit length: " << BN_num_bits(_publicKey.get())
            << "\n"
            << std::endl;
  // }
  // --------------------------------------------------------------
}
/******************************************************************************/