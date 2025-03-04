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

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag)
    : _debugFlag(debugFlag), _sha(std::make_shared<MyCryptoLibrary::SHA1>()) {
  std::string hexServerKey{};
  if (std::getenv("AES_256_KEY_SERVER_SET_4_PROBLEM_28") != nullptr) {
    hexServerKey = std::getenv("AES_256_KEY_SERVER_SET_4_PROBLEM_28");
  } else {
    const std::string errorMessage{
        "Server log | server key 'AES_256_KEY_SERVER_SET_4_PROBLEM_28' must be "
        "setup prior to this call"};
    throw std::invalid_argument(errorMessage);
  }
  Server::_keyServer = Server::hexToBytes(hexServerKey);
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
  inputKeyPrepended = Server::prependKey(inputV);
  std::string inputKeyPrependedS(inputKeyPrepended.begin(),
                                 inputKeyPrepended.end());
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
 * @return The true if the hash(key sender || message) == mac, false otherwise
 */
bool Server::checkMac(const std::string &message,
                      const std::vector<unsigned char> &mac) {
  const std::vector<unsigned char> messageV(message.begin(), message.end());
  Server::setKey(message);
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
 * @brief This method sets the key to be used as a prefix in a hash
 * calculation.
 *
 * This method sets the key to be used as a prefix in a hash calculation,
 * for a given sender of a message
 */
void Server::setKey(const std::string &message) {
  if (message.size() == 0) {
    const std::string errorMessage{
        "Server log | message empty to be look up in the database"};
    throw std::invalid_argument(errorMessage);
  }
  std::string sender{}, symmetricKey{};
  std::vector<unsigned char> fileContentEncryptedV =
      Server::extractFile(_keysFileLocation);
  std::string keyServerS(Server::_keyServer.begin(), Server::_keyServer.end());
  std::string hexStrEncrypted(fileContentEncryptedV.begin(),
                              fileContentEncryptedV.end());
  fileContentEncryptedV.clear();
  fileContentEncryptedV = Server::hexToBytes(hexStrEncrypted);
  std::string fileContentPlaintext(fileContentEncryptedV.size(), '\0');
  Server::decrypt(fileContentEncryptedV, keyServerS, fileContentPlaintext,
                  Server::_iv);
  nlohmann::ordered_json symmetricKeys =
      nlohmann::json::parse(fileContentPlaintext);
  nlohmann::ordered_json transaction = nlohmann::json::parse(message);
  bool foundKey{false};
  try {
    sender = transaction.at("sender");
    for (const auto &user : symmetricKeys.at("users")) {
      if (user.at("name") == sender) {
        symmetricKey = user.at("symmetric_key");
        foundKey = true;
        if (_debugFlag == true) {
          std::cout << "\n\nServer log | Key from " + sender +
                           " (hex):   " + symmetricKey
                    << std::endl;
        }
      }
    }
  } catch (const std::exception &e) {
    std::cout << "Caught in Server::setKey: " << e.what() << std::endl;
    throw std::invalid_argument("Server log | Bad input for the json library");
  }
  if (foundKey == false) {
    const std::string errorMessage =
        "Server log | " + sender + " symmetric key not found in the database";
    throw std::invalid_argument(errorMessage);
  }
  // check minimum size of the key
  if (symmetricKey.size() < SHA_DIGEST_LENGTH) {
    const std::string errorMessage = "Server log | " + sender +
                                     " symmetric key found in the database "
                                     "does not meet minimum size requirements";
    throw std::invalid_argument(errorMessage);
  }
  // set key in servers data structure
  Server::_key.clear();
  Server::_key.assign(symmetricKey.begin(), symmetricKey.end());
}
/******************************************************************************/
/**
 * @brief This method prepend the key to the input that is going to be hashed
 *
 * This method prepend the key to the input that is going to be hashed
 *
 * @param inputV The input that is going to be hashed
 */
std::vector<unsigned char>
Server::prependKey(const std::vector<unsigned char> &inputV) {
  const std::string message(inputV.begin(), inputV.end());
  Server::setKey(message);
  std::vector<unsigned char> inputWithKey = Server::_key;
  for (unsigned char c : inputV) {
    inputWithKey.emplace_back(c);
  }
  return inputWithKey;
}
/******************************************************************************/
/**
 * @brief This method extract the content of a given file
 *
 * This method will extract the content of a given file location
 *
 * @return The content of a file in a string format
 */
std::vector<unsigned char>
Server::extractFile(const std::string &fileLocation) {
  std::vector<unsigned char> content;
  std::ifstream inFile(fileLocation);
  if (!inFile) {
    std::cerr << "Error opening file." << std::endl;
  }
  // Read the content of the file into a string
  std::stringstream buffer;
  buffer << inFile.rdbuf();
  std::string hexCiphertext = buffer.str();
  content.assign(hexCiphertext.begin(), hexCiphertext.end());
  std::vector<unsigned char> ciphertext(content.size() + AES_BLOCK_SIZE);
  ciphertext.assign(content.begin(), content.end());
  return ciphertext;
}
/******************************************************************************/
/**
 * @brief This method will deal with errors during encryption/decryption
 *
 * This method will deal with errors during encryption/decryption, including
 * printing error messages
 */
void Server::handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}
/******************************************************************************/
/**
 * @brief This method will decrypt the ciphertext using aes256 cbc mode
 *
 * This method will decrypt the ciphertext using aes256 cbc mode, using key
 * and iv in the process, returning by reference in the plaintext the result
 *
 * @param ciphertext The input to be decrypted
 * @param key The key to be used in the decryption
 * @param plaintext The plaintext resulting of the decryption
 * @param iv The initialization vector used in the decryption
 */
void Server::decrypt(const std::vector<unsigned char> &ciphertext,
                     const std::string &key, std::string &plaintext,
                     unsigned char *iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    Server::handleErrors();

  int len;
  int plaintext_len;
  std::vector<unsigned char> plaintextV;
  // Initialize decryption operation
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                         reinterpret_cast<const unsigned char *>(key.c_str()),
                         iv) != 1)
    Server::handleErrors();

  // Provide the message to be decrypted
  if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext.data(), &len,
                        ciphertext.data(), ciphertext.size()) != 1)
    Server::handleErrors();
  plaintext_len = len;

  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(plaintext_len); // Resize plaintext to the actual length
  plaintextV.assign(plaintext.begin(), plaintext.end());
  Server::removePKCS7Padding(plaintextV);
  plaintext.assign(plaintextV.begin(), plaintextV.end());
}
/******************************************************************************/
/**
 * @brief This method will remove the padding PKCDS7
 *
 * This method will remove the padding PKCDS7 from the data, in place
 *
 * @param data The input to be removed the padding, by reference
 */
void Server::removePKCS7Padding(std::vector<unsigned char> &data) {
  if (data.empty())
    return;

  // Get the last byte value
  unsigned char paddingValue = data.back();

  // Ensure the padding is valid
  if (paddingValue > 0 && paddingValue <= data.size()) {
    size_t paddingStart = data.size() - paddingValue;
    if (std::all_of(
            data.begin() + paddingStart, data.end(),
            [paddingValue](unsigned char c) { return c == paddingValue; })) {
      // Erase the padding bytes
      data.erase(data.begin() + paddingStart, data.end());
    }
  }
}
/******************************************************************************/
/**
 * @brief This method will convert hexadecimal string to byte vector
 *
 * This method will convert hexadecimal string to byte vector, using zero
 * alignment
 *
 * @param hexStr The input to be converted
 *
 * @return The byte vector resulting of the conversion
 */
std::vector<unsigned char> Server::hexToBytes(const std::string &hexStr) {
  std::vector<unsigned char> bytes;
  for (size_t i = 0; i < hexStr.length(); i += 2) {
    std::string byteString = hexStr.substr(i, 2);
    unsigned char byte =
        static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    bytes.push_back(byte);
  }
  return bytes;
}
/******************************************************************************/
