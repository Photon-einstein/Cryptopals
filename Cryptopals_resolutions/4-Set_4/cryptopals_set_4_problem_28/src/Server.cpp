#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <stdexcept>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctime>
#include <string.h>
#include <cstring>
#include <string>
#include <math.h>
#include <ctype.h>
#include <assert.h>
#include <vector>
#include <iostream>
#include <cstddef>
#include <unordered_map>
#include <bits/stdc++.h>
#include <cctype>
#include <fstream>
#include <random>
#include <map>
#include <algorithm> // for copy() and assign()
#include <iterator> // for back_inserter
#include <string.h>
#include <string>
#include <memory>
#include <climits>
#include <random>
#include <cstdlib>

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server() {
    _sha = std::make_shared<MyCryptoLibrary::SHA1>();
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
    if (_debugFlag == true) {
        printMessage("SHA1 with library    | " + originalMessage + " (hex): ", output, PrintFormat::HEX);
    }

  return output;
}
/******************************************************************************/
/**
 * @brief Calculates the SHA1 without Openssl library
 *
 * This function takes two integers as input and returns their sum.
 *
 * @param inputV The characters to be hashed in a vector format
 * @param originalMessage The characters to be hashed in a string format
 * @return The hash SHA1 of the inputV characters
 */
std::vector<unsigned char> Server::hashSHA1(const std::vector<unsigned char> &inputV, const std::string &originalMessage) {
  std::vector<unsigned char> output = _sha->hash(inputV); 
  // Optionally, print for debug purposes
  if (_debugFlag == true) {
      printMessage("SHA1 without library | " + originalMessage + " (hex): ", output, PrintFormat::HEX);
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
    printf("\n");
}
/******************************************************************************/
void Server::setPlaintext(const int sizePlaintext, bool randomPlaintext, const std::string &plaintext) {
  if (sizePlaintext < 1) {
    throw std::invalid_argument("Server log | Bad limit boundaries for the plaintext generation");
  }
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,255); // distribute results between 0 and 255 inclusive
  int i;
  unsigned char c;
  if(_debugFlag == true) {
    printf("\nServer log | Plaintext generated (hex):   ");
  }
  if (randomPlaintext) {
    for (i = 0; i < sizePlaintext; ++i) {
      c = dist1(gen);
      _plaintextV.push_back(c);
      _plaintext.push_back(c);
      if (_debugFlag == true) {
        printf("%.2x ", (unsigned char)c);
      }
    }
  } else {
    _plaintext = plaintext;
    for (i = 0; i < plaintext.size(); ++i) {
      _plaintextV.push_back(plaintext[i]);
      if (_debugFlag == true) {
        printf("%.2x ", (unsigned char)_plaintextV[i]);
      }
    }
  }
  if (_debugFlag) {
    printf("\n");
  }
}
/******************************************************************************/
const std::vector<unsigned char> Server::getPlaintextV() {
  return _plaintextV;
}
/******************************************************************************/
const std::string Server::getPlaintext() {
  return _plaintext;
}
/******************************************************************************/
