#include <fstream>
#include <iostream>
#include <limits.h>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool debugFlag)
    : _debugFlag{debugFlag}, _server{server} {}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method extracts the message intercepted
 *
 * This method will extract the message intercepted from a given file location
 *
 * @param messageLocation The location of the message to be extracted
 * @return The message intercepted in a string format
 */
std::string Attacker::extractMessage(const std::string &messageLocation) const {
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
  if (Attacker::_debugFlag) {
    std::cout << "Attacker log | File content read at the file "
              << messageLocation << "':\n'" << content << "'." << std::endl;
  }
  return content;
}
/******************************************************************************/
/**
 * @brief This method will append the padding to the message
 *
 * This method will append the padding to the message according to
 * the requirements of the MD4 hash
 *
 * @param message The message to be padded
 * @return The message padded
 */
std::vector<unsigned char>
Attacker::computeMD4padding(const std::string &message) const {
  // Initialize padded input vector with original message
  uint64_t messageLength{message.size() * CHAR_BIT};
  std::vector<unsigned char> inputVpadded(message.begin(), message.end());
  // Step 1: Append the bit '1' (equivalent to adding 0x80)
  inputVpadded.push_back(0x80);

  // Step 2: Append '0' bits until the length of the message (in bits) is
  // congruent to 448 mod 512
  while ((inputVpadded.size() * 8) % 512 != 448) {
    inputVpadded.push_back(0x00);
  }

  // Step 3: Append the original message length (ml) as a 64-bit little-endian
  // uint64_t _ml is already in bits
  for (int i = 0; i < 8; ++i) {
    inputVpadded.push_back(
        static_cast<unsigned char>((messageLength >> (i * 8)) & 0xFF));
  }
  if (Attacker::_debugFlagExtreme) {
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