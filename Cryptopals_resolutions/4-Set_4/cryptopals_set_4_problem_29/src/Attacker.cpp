#include <fstream>
#include <iostream>
#include <limits.h>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool writeToFile) {
  _sha = std::make_shared<MyCryptoLibrary::SHA1>();
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method will try perform the Length Extension Attack at
 * the SHA1
 *
 * This method will try to perform the Length Extension Attack at the SHA1
 *
 * @return A bool value, true if the attack was successful,
 * false otherwise
 */
bool Attacker::lengthExtensionAttackAtSHA1() {
  std::string message = Attacker::extractMessage(Attacker::messageLocation);
  MessageFormat::MessageParsed msgParsed =
      MessageExtractionFacility::parseMessage(message, Attacker::_debugFlag);
  Attacker::computeSHA1padding(msgParsed.msg);
  return Attacker::tamperMessageTry(msgParsed);
}
/******************************************************************************/
/**
 * @brief This method extracts the message intercepted
 *
 * This method will extract the message intercepted
 *
 * @param messageLocation The location of the message to be extracted
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
 * This method will append the padding according to the requirements
 * of the SHA1 hash
 *
 * @param message The message to be padded
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
  const std::vector<unsigned char> appendMessageGoalV(appendMessageGoal.begin(),
                                                      appendMessageGoal.end());
  std::vector<unsigned char> padding, newMessage, macByteFormat, newMac;
  std::string keyAndMessage{};
  const char dummyChar = '#';
  SHA1InternalState::SHA1InternalState sha1InternalState;
  // calculation of the new MAC TBD
  // conversion hex to bytes of the mac
  macByteFormat = Attacker::hexToBytes(messageParsed.mac);
  if (Attacker::_debugFlag) {
    std::cout << "\nAttacker log | Size of the mac = " << macByteFormat.size()
              << " bytes" << std::endl;
  }
  // extraction of the internal state of the SHA1 of the current mac
  sha1InternalState = Attacker::extractionSHA1InternalState(macByteFormat);
  // Computation of the new MAC using SHA-1’s state from the intercepted message
  newMac = _sha->hash(
      appendMessageGoalV, sha1InternalState.internalState[0],
      sha1InternalState.internalState[1], sha1InternalState.internalState[2],
      sha1InternalState.internalState[3], sha1InternalState.internalState[4]);
  // Trial and error to find the length of private key of the server
  for (keyLength = 1; keyLength <= maxKeySize; ++keyLength) {
    std::string keyAndMessage(keyLength, dummyChar);
    keyAndMessage += messageParsed.msg;
    padding = Attacker::computeSHA1padding(keyAndMessage);
    // construction of new forged message:   msg || padding || forged msg
    newMessage.clear();
    newMessage.assign(messageParsed.msg.begin(), messageParsed.msg.end());
    newMessage.insert(newMessage.end(), padding.begin(), padding.end());
    // Test the keyLength in the server
  }
  return true;
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
std::vector<unsigned char> Attacker::hexToBytes(const std::string &hexStr) {
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
/**
 * @brief This method will extract the internal state of the SHA1
 *
 * This method will extract the internal state of the SHA1 from a mac in a byte
 * format input
 *
 * @param macByteFormat The SHA1 mac in a byte format
 *
 * @return The internal state of the SHA1
 */
SHA1InternalState::SHA1InternalState Attacker::extractionSHA1InternalState(
    const std::vector<unsigned char> &macByteFormat) {
  SHA1InternalState::SHA1InternalState sha1InternalState;
  const int internalStateRegisterSize{5}; // 32 bit / 4 byte each register
  uint32_t registerSha1Value;
  if (macByteFormat.size() != Attacker::_sha1DigestLength) {
    const std::string errorMessage =
        "Attacker log | invalid size of the input macByteFormat at the method "
        "Attacker::extractionSHA1InternalState,"
        " expected " +
        std::to_string(Attacker::_sha1DigestLength) +
        std::string(" bytes and got ") + std::to_string(macByteFormat.size()) +
        " bytes instead.";
    throw std::invalid_argument(errorMessage);
  }
  for (int registerSha1Counter = 0;
       registerSha1Counter < internalStateRegisterSize; ++registerSha1Counter) {
    registerSha1Value =
        static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4]) << 24 |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 1])
         << 16) |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 2])
         << 8) |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 3]));
    sha1InternalState.internalState.push_back(registerSha1Value);
  }
  return sha1InternalState;
}
/******************************************************************************/