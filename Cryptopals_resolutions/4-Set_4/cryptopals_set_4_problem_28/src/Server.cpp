#include <iostream>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <random>
#include <stdexcept>

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag)
    : _keyLength(SHA_DIGEST_LENGTH * 2), _debugFlag(debugFlag) {
  Server::setKey(Server::_keyLength);
  _sha = std::make_shared<MyCryptoLibrary::SHA1>();
}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
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
Server::hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
                            const std::string &originalMessage) {
  std::vector<unsigned char> output, inputKeyPrepended;
  inputKeyPrepended = Server::prependKey(inputV);
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
  if (_debugFlag == true) {
    printMessage("\nSHA1 with library    | '" + originalMessage + "' (hex): ",
                 output, PrintFormat::HEX);
  }

  return output;
}
/******************************************************************************/
/**
 * @brief Calculates the SHA-1 using a custom made library
 *
 * This method perform the hash SHA-1 of the message with a custom made library
 *
 * @param inputV The characters to be hashed in a vector format
 * @param originalMessage The characters to be hashed in a string format
 * @return The hash SHA1 of the inputV characters
 */
std::vector<unsigned char>
Server::hashSHA1(const std::vector<unsigned char> &inputV,
                 const std::string &originalMessage) {
  ;
  std::vector<unsigned char> inputKeyPrepended, output;
  inputKeyPrepended = Server::prependKey(inputV),
  output = _sha->hash(inputKeyPrepended);
  // Optionally, print for debug purposes
  if (_debugFlag == true) {
    printMessage("\nSHA1 without library | '" + originalMessage + "' (hex): ",
                 output, PrintFormat::HEX);
  }
  return output;
}
/******************************************************************************/
/**
 * @brief This method does the verification of a given mac and the corresponding
 * message
 *
 * This method does the verification of a given mac and the corresponding
 * message, checking if the message was tampered
 *
 * @param message The message that was hashed
 * @param mac The corresponding mac value of the given message
 * @return The true if the hash(key || message) == mac, false otherwise
 */
bool Server::checkMac(const std::string &message,
                      const std::vector<unsigned char> &mac) {
  const std::vector<unsigned char> messageV(message.begin(), message.end());
  const std::vector<unsigned char> serverMac =
      Server::hashSHA1(messageV, message);
  bool output = (serverMac == mac);
  if (_debugFlag == true) {
    if (output) {
      printf("\nServer log | 'checkMac' test for message: '%s' mac verdict "
             "match.",
             message.c_str());
    } else {
      printf("\nServer log | 'checkMac' test for message: '%s' mac verdict "
             "does not match.",
             message.c_str());
    }
  }
  return output;
}
/******************************************************************************/
/**
 * @brief This method print the hash value and the original message to be
 * hashed.
 *
 * This method print the hash value and the original message in the specified
 * format.
 *
 * @param originalMessage The characters to be hashed in a string format
 * @param hash The originalMessage hashed in a vector format
 * @param format The format to be used in the print of the hash value (HEX,
 * DECIMAL, ASCII)
 */
void Server::printMessage(const std::string &originalMessage,
                          const std::vector<unsigned char> &hash,
                          PrintFormat::Format format) {
  std::cout << originalMessage;
  switch (format) {
  case PrintFormat::HEX:
    // Print in hexadecimal format
    for (unsigned char c : hash) {
      printf("%02x", c);
    }
    break;
  case PrintFormat::DECIMAL:
    // Print in decimal format
    for (unsigned char c : hash) {
      printf("%d ", c);
    }
    break;
  case PrintFormat::ASCII:
    // Print in ascii format
    for (unsigned char c : hash) {
      printf("%d ", c);
    }
    break;
  }
  printf("\n");
}
/******************************************************************************/
/**
 * @brief This method sets the plaintext to be hashed in a server's variable.
 *
 * This method sets the plaintext to be hashed, randomly or from the input
 * string
 *
 * @param sizePlaintext The size of the random plaintext to be generated
 * @param randomPlaintext A bool flag that signal if the plaintext is to be
 * generated randomly or not
 * @param plaintext The input plaintext string if the plaintext is to be set
 * deterministically
 */
void Server::setPlaintext(const int sizePlaintext, bool randomPlaintext,
                          const std::string &plaintext) {
  if (sizePlaintext < 1) {
    throw std::invalid_argument(
        "Server log | Bad limit boundaries for the plaintext generation");
  }
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  int i;
  unsigned char c;
  if (randomPlaintext) {
    if (_debugFlag == true) {
      printf("\nServer log | Plaintext generated (hex):   '");
    }
    for (i = 0; i < sizePlaintext; ++i) {
      c = dist1(gen);
      _plaintextV.push_back(c);
      _plaintext.push_back(c);
      if (_debugFlag == true) {
        printf("%.2x ", (unsigned char)c);
      }
    }
  } else {
    if (_debugFlag == true) {
      printf("\nServer log | Plaintext received (ascii):   '");
    }
    _plaintext = plaintext;
    for (i = 0; i < plaintext.size(); ++i) {
      _plaintextV.push_back(plaintext[i]);
      if (_debugFlag == true) {
        printf("%c", (unsigned char)_plaintextV[i]);
      }
    }
  }
  if (_debugFlag) {
    printf("'\n");
  }
}
/******************************************************************************/
/**
 * @brief Returns the plaintext stored in the server
 *
 * This method returns the plaintext stored in the server, in a vector format
 *
 * @return The plaintext stored in the server, as a vector
 */
const std::vector<unsigned char> Server::getPlaintextV() { return _plaintextV; }
/******************************************************************************/
/**
 * @brief Returns the plaintext stored in the server
 *
 * This method returns the plaintext stored in the server, in a string format
 *
 * @return The plaintext stored in the server, as a string
 */
const std::string Server::getPlaintext() { return _plaintext; }
/******************************************************************************/
/**
 * @brief This method sets the key to be used as a prefix in a hash calculation.
 *
 * This method sets the key to be used as a prefix in a hash calculation, with
 * a given size
 *
 * @param sizeKey The size of the random key to be generated
 */
void Server::setKey(const std::size_t sizeKey) {
  if (sizeKey < SHA_DIGEST_LENGTH) {
    throw std::invalid_argument("Server log | Bad size for the key generation");
  }
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  int i;
  unsigned char k_n;
  if (_debugFlag == true) {
    printf("\nServer log | Key generated (hex):   ");
  }
  for (i = 0; i < sizeKey; ++i) {
    k_n = dist1(gen);
    _key.push_back(k_n);
    if (_debugFlag == true) {
      printf("%.2x", (unsigned char)k_n);
    }
  }
  if (_debugFlag) {
    printf("\n");
  }
}
/******************************************************************************/
/**
 * @brief This method prepend the key to input that is going to be hashed
 *
 * This method prepend the key to the input that is going to be hashed
 *
 * @param inputV The input that is going to be hashed
 */
std::vector<unsigned char>
Server::prependKey(const std::vector<unsigned char> &inputV) {
  std::vector<unsigned char> inputWithKey = Server::_key;
  for (unsigned char c : inputV) {
    inputWithKey.emplace_back(c);
  }
  return inputWithKey;
}
/******************************************************************************/
