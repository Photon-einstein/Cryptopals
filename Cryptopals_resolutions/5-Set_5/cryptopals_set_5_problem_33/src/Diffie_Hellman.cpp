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
  }
}
/******************************************************************************/
MyCryptoLibrary::Diffie_Hellman::~Diffie_Hellman() {}
/******************************************************************************/
void MyCryptoLibrary::Diffie_Hellman::generatePrivateKey() {
  // The private key 'a' must be 1 < a < p-1.
  // So, we need to generate a random number 'x' such that 0 <= x < (p-2).
  // Then, set 'a = x + 2'. This ensures 'a' is in the range [2, p-1).
  MessageExtractionFacility::UniqueBIGNUM rangeForRand =
      MessageExtractionFacility::UniqueBIGNUM(_p.get());
  // Subtract 2: p - 2
  if (!BN_sub_word(_p.get(), 2)) {
    // BN_sub_word returns 0 if subtraction causes negative result or fails
    // For large primes, this should not happen if p > 2.
    throw std::runtime_error(
        "BN_sub_word failed for random range calculation.");
  }
  if (BN_is_zero(_p.get()) || BN_is_negative(_p.get())) {
    throw std::invalid_argument("Modulus p is too small for generating a valid "
                                "private key range (p must be > 2).");
  }
  // Generate random number 'x' such that 0 <= x < (p-2)
  // BN_rand_range(rnd, range) generates 0 <= rnd < range
  if (!BN_rand_range(_privateKey.get(), rangeForRand.get())) {
    // BN_rand_range returns 0 on error
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to generate random private key: " +
                             std::string(err_buf));
  }

  // Add 2 to 'x' to get 'a' in the range [2, p-1)
  if (!BN_add_word(_privateKey.get(), 2)) {
    // BN_add_word returns 0 on error
    throw std::runtime_error("Failed to adjust private key to range [2, p-1).");
  }
  // --- Optional: For debugging/logging (remove in production) ---
  std::cout << "Generated private key (hex): "
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