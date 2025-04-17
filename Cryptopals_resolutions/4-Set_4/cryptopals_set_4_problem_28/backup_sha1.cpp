#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <stdexcept>

/**
 * @brief Calculates the SHA-1 hash using the OpenSSL library
 *
 * This method perform the hash SHA-1 of the message using the OpenSSL library
 *
 * @param inputV The characters to be hashed in a vector format
 * @param originalMessage The characters to be hashed in a string format
 * @return The hash SHA1 of the inputV characters
 */
std::vector<unsigned char>
hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
                    const std::string &originalMessage) {
  std::vector<unsigned char> output, inputKeyPrepended;
  inputKeyPrepended = inputV; // Server::prependKey(inputV);
  // Create a new digest context
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }
  // Initialize the context to use the SHA-1 digest algorithm
  if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestInit_ex failed");
  }
  // Provide the message to be hashed
  if (EVP_DigestUpdate(ctx, inputKeyPrepended.data(),
                       inputKeyPrepended.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestUpdate failed");
  }
  // Finalize the digest
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &hashLength) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  }
  // Clean up
  EVP_MD_CTX_free(ctx);
  // Resize output vector to the digest length and copy hash data
  output.assign(hash, hash + hashLength);
  // Optionally, print for debug purposes
  //   if (_debugFlag == true) {
  //     printMessage("\nSHA1 with library    | '" + originalMessage + "' (hex):
  //     ",
  //                  output, PrintFormat::HEX);
  //   }
  return output;
}