#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server() {
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
/**
 * @brief Calculates the SHA1 hash using the Openssl library
 *
 * This function takes two integers as input and returns their sum.
 *
 * @param inputV The characters to be hashed in a vector format
 * @param description The characters to be hashed in a string format
 * @return The hash SHA1 of the inputV characters
 */

std::vector<unsigned char> Server::hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
    const std::string &description) {
    std::vector<unsigned char> output;

    // Create a new digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    // Initialize the context to use the SHA-1 digest algorithm
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Provide the message to be hashed
    if (EVP_DigestUpdate(ctx, inputV.data(), inputV.size()) != 1) {
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
    if (debugFlag == true) {
        //printMessage("SHA1 with library | " + description + " (hex):", output, PrintFormat::HEX);
    }

  return output;
}
/******************************************************************************/