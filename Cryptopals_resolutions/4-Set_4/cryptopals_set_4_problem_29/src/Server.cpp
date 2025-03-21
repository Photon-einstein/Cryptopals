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
  } else {
    const std::string errorMessage{
        "Server log | server key 'KEY_SERVER_SET_4_PROBLEM_29' must be "
        "setup prior to this call"};
    throw std::invalid_argument(errorMessage);
  }
  Server::_keyServer = MessageExtractionFacility::hexToBytes(hexServerKey);
}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
/**
 * @brief This method will validate if a given message produces the
 * given message authentication code (MAC)
 *
 * This method will validate if a given message produces the
 * given message authentication code (MAC), it will perform the following
 * test: SHA1(private server key || msg) == mac
 *
 * @param msg The message to be authenticated
 * @param mac The message authentication code (mac) to be validated in
 * hexadecimal format
 *
 * @return A bool value, true if the mac received matches the
 * mac produced by the server, false otherwise
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
