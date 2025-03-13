#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool writeToFile) {
  _sha = std::make_shared<MyCryptoLibrary::SHA1>();
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method extracts the message intercepted
 *
 * This method will extract the message intercepted
 *
 * @return The message intercepted in a string format
 */
std::string Attacker::extractMessage(const std::string &messageLocation) {
  std::ifstream file(messageLocation);
  if (!file) {
    const std::string errorMessage =
        "Attacker log | " + messageLocation + " file not found";
    throw std::invalid_argument(errorMessage);
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string content = buffer.str();
  file.close();
  if (Attacker::debugFlag) {
    std::cout << "Attacker log | File content read at the file "
              << messageLocation << "':\n'" << content << "'." << std::endl;
  }
  return content;
}
/******************************************************************************/
/**
 * @brief This method parses the message intercepted
 *
 * This method will parses the message intercepted,
 * extracting url, message and mac fields
 *
 * @return The message parsed
 */
MessageFormat::MessageParsed
Attacker::parseMessage(const std::string &message) {
  if (message.empty()) {
    const std::string errorMessage =
        "Attacker log | message empty at the method Attacker::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  std::size_t queryPos, macPos;
  std::string baseUrl, query, mac;
  queryPos = message.find("?");
  MessageFormat::MessageParsed msgParsed;
  if (queryPos == std::string::npos) {
    const std::string errorMessage = "Attacker log | query message empty at "
                                     "the method Attacker::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  macPos = message.find("&mac=");
  if (macPos == std::string::npos) {
    const std::string errorMessage =
        "Attacker log | mac not found at the method Attacker::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  baseUrl = message.substr(0, queryPos);
  query = message.substr(queryPos + 1, macPos - queryPos - 1);
  mac = message.substr(macPos + 5);
  msgParsed.url = baseUrl;
  msgParsed.msg = query;
  msgParsed.mac = mac;
  if (Attacker::debugFlag) {
    std::cout << "\nAttacker log | Message Parsed content:\nbase url: '"
              << msgParsed.url << "'\nmessage: '" << msgParsed.msg
              << "'\nmac: '" << msgParsed.mac << "'" << std::endl;
  }
  return msgParsed;
}
/******************************************************************************/