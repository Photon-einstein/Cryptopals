#include <fstream>
#include <iostream>
#include <limits.h>
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
/**
 * @brief This method will append the padding to the message
 *
 * This method will append the padding according to the requirements
 * of the SHA1 hash
 *
 * @return The message padded
 */
std::vector<unsigned char>
Attacker::computeSHA1padding(const std::string &message) {
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
  if (Attacker::debugFlag) {
    std::cout << "\nAttacker log | Message padded:\n'";
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
/**
 * @brief This method will try to tamper a message
 *
 * This method will try to tamper a message intercepted and
 * deceive the server with another message authentication
 * code (MAC)
 *
 * @param messageParsed The content of the message intercepted, parsed already
 * @return A bool value, true if the attack was successful,
 * false otherwise
 */
bool Attacker::tamperMessageTry(MessageFormat::MessageParsed &messageParsed) {
  if (messageParsed.url.size() == 0 || messageParsed.msg.size() == 0 ||
      messageParsed.mac.size() == 0) {
    const std::string errorMessage =
        "Attacker log | messageParsed empty as an input field at the method "
        "Attacker::tamperMessageTry";
    throw std::invalid_argument(errorMessage);
  }
  const unsigned int maxKeySize{64};
  unsigned int keyLength;
  const std::string appendMessageGoal{"&admin=true"};
  std::vector<unsigned char> padding, newMessage;
  std::string keyAndMessage{};
  const char dummyChar = '#';
  for (keyLength = 1; keyLength <= maxKeySize; ++keyLength) {
    std::string keyAndMessage(keyLength, dummyChar);
    keyAndMessage += messageParsed.msg;
    padding = Attacker::computeSHA1padding(keyAndMessage);
    // construction of new forged message:   msg || padding || forged msg
    newMessage.clear();
    newMessage.assign(messageParsed.msg.begin(), messageParsed.msg.end());
    newMessage.insert(newMessage.end(), padding.begin(), padding.end());
    // calculation of the new MAC TBD
  }
  return true;
}
/******************************************************************************/
