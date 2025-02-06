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
 * @param originalMessage The characters to be hashed in a string format
 * @return The hash SHA1 of the inputV characters
 */

std::vector<unsigned char> Server::hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
    const std::string &originalMessage) {
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
        printMessage("SHA1 with library | " + originalMessage + " (hex): ", output, PrintFormat::HEX);
    }

  return output;
}
/******************************************************************************/
/**
 * @brief This method print the hash value and the original message to be hashed.
 *
 * This method print the hash value and the original message in the specified format.
 *
 * @param originalMessage The characters to be hashed in a string format
 * @param hash The originalMessage hashed in a vector format
 * @param format The format to be used in the print of the hash value.
 */
void Server::printMessage(const std::string& originalMessage, const std::vector<unsigned char> &hash, PrintFormat::Format format) {
    std::cout<<originalMessage;
    switch (format) {
        case PrintFormat::HEX:
            // Print in hexadecimal format
            for(unsigned char c : hash) {
                printf("%02x", c);
            }
            break;
        case PrintFormat::DECIMAL:
            // Print in decimal format
            for(unsigned char c : hash) {
                printf("%d ", c);
            }
            break;
        case PrintFormat::ASCII:
            // Print in ascii format
            for(unsigned char c : hash) {
                printf("%d ", c);
            }
            break;
    }
}
/******************************************************************************/