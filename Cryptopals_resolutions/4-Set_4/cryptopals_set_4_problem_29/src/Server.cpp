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

#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag)
    : _debugFlag(debugFlag), _sha(std::make_shared<MyCryptoLibrary::SHA1>()) {
  std::string hexServerKey{};
  if (std::getenv("KEY_SERVER_SET_4_PROBLEM_29") != nullptr) {
    hexServerKey = std::getenv("KEY_SERVER_SET_4_PROBLEM_29");
    std::cout << "Key server: " << hexServerKey << " \n" << std::endl;
  } else {
    const std::string errorMessage{
        "Server log | server key 'KEY_SERVER_SET_4_PROBLEM_29' must be "
        "setup prior to this call"};
    throw std::invalid_argument(errorMessage);
  }
  Server::_keyServer = MessageExtractionFacility::hexToBytes(hexServerKey);
  std::cout << "Server::_keyServer with size: "
            << std::to_string(Server::_keyServer.size()) << " bytes."
            << std::endl;
}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
/**
 * @brief This method will validate if a given message has produces the
 * given message authentication code (MAC)
 *
 * This method will validate if a given message has produces the
 * given message authentication code (MAC), it will perform the following
 * test: SHA1(private server key || msg) == mac
 *
 * @param msg The message to be authenticated
 * @param mac The message authentication code (mac) to be validated in
 * hexadecimal format
 *
 * @return A bool value, true if the mac received matches the
 * mac produced by the server
 */
bool Server::validateMac(const std::vector<unsigned char> &msg,
                         const std::vector<unsigned char> &mac) {
  if (mac.size() != SHA_DIGEST_LENGTH) {
    const std::string errorMessage = "Server log | mac received in the method "
                                     "Server::validateMac does not match the " +
                                     std::to_string(SHA_DIGEST_LENGTH) +
                                     std::string(" length in bytes.");
    throw std::invalid_argument(errorMessage);
  } else if (Server::_keyServer.empty()) {
    throw std::runtime_error("Server log | Server::_keyServer is empty!");
  }
  std::vector<unsigned char> msgToValidateV(Server::_keyServer.begin(),
                                            Server::_keyServer.end());
  std::vector<unsigned char> macServer;
  msgToValidateV.insert(msgToValidateV.end(), msg.begin(), msg.end());
  macServer = Server::_sha->hash(msgToValidateV);
  return macServer == mac;
}
/******************************************************************************/
/**
 * @brief This method will append the padding to the message
 *
 * This method will append the padding according to the requirements
 * of the SHA1 hash
 *
 * @param message The message to be padded
 * @return The message padded
 */
std::vector<unsigned char>
Server::computeSHA1padding(const std::string &message) {
  // Initialize padded input vector with original message
  uint64_t messageLenght{message.size() * CHAR_BIT};
  std::vector<unsigned char> inputVpadded(message.begin(), message.end());
  // Step 1: Append the bit '1' (equivalent to adding 0x80)
  inputVpadded.push_back(0x80);

  // Step 2: Append '0' bits until the length of the message (in bits) is
  // congruent to 448 mod 512
  while ((inputVpadded.size() * 8) % 512 != 448) {
    inputVpadded.push_back(0x00);
  }

  // Step 3: Append the original message length (ml) as a 64-bit big-endian
  // integer _ml is already in bits
  for (int i = 7; i >= 0; --i) {
    inputVpadded.push_back(
        static_cast<unsigned char>((messageLenght >> (i * 8)) & 0xFF));
  }
  if (Server::_debugFlagExtreme) {
    std::cout << "\nServer log | Message padded:\n'";
    for (std::size_t i = 0; i < inputVpadded.size(); ++i) {
      if (i < message.size()) {
        printf("%c", inputVpadded[i]);
      } else {
        printf(" %02x", inputVpadded[i]);
      }
    }
    std::cout << "'.\n" << std::endl;
  }
  return inputVpadded;
}
/******************************************************************************/
