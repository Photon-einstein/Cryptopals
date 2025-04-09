#include <fstream>
#include <iostream>
#include <limits.h>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool debugFlag)
    : _debugFlag{debugFlag}, _md4{std::make_shared<MyCryptoLibrary::MD4>()},
      _server{server} {}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method will try perform the Length Extension Attack at
 * the SHA1
 *
 * This method will try to perform the Length Extension Attack at the MD4
 *
 * @return A bool value, true if the attack was successful,
 * false otherwise
 */
bool Attacker::lengthExtensionAttackAtMD4() {
  std::string message = Attacker::extractMessage(Attacker::_messageLocation);
  MessageFormat::MessageParsed msgParsed =
      MessageExtractionFacility::parseMessage(message, Attacker::_debugFlag);
  Attacker::computeMD4padding(msgParsed._msg);
  return Attacker::tamperMessageTry(msgParsed);
}
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
/**
 * @brief This method will extract the internal state of the MD4
 *
 * This method will extract the internal state of the MD4 from a mac in a
 * byte format input
 *
 * @param macByteFormat The MD4 mac in a byte format
 * @return The internal state of the SHA1
 */
MD4InternalState::MD4InternalState Attacker::extractionMD4InternalState(
    const std::vector<unsigned char> &macByteFormat) {
  MD4InternalState::MD4InternalState md4InternalState;
  const int internalStateRegisterSize{4}; // 32 bit / 4 byte each register
  if (macByteFormat.size() != Attacker::_md4DigestLength) {
    const std::string errorMessage =
        "Attacker log | invalid size of the input macByteFormat at the method "
        "Attacker::extractionSHA1InternalState,"
        " expected " +
        std::to_string(Attacker::_md4DigestLength) +
        std::string(" bytes and got ") + std::to_string(macByteFormat.size()) +
        " bytes instead.";
    throw std::invalid_argument(errorMessage);
  }
  for (int registerSha1Counter = 0;
       registerSha1Counter < internalStateRegisterSize; ++registerSha1Counter) {
    uint32_t registerSha1Value =
        static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4]) |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 1])
         << 8) |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 2])
         << 16) |
        (static_cast<uint32_t>(macByteFormat[registerSha1Counter * 4 + 3])
         << 24);
    md4InternalState._internalState.push_back(registerSha1Value);
  }
  return md4InternalState;
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
 * @return A bool value, true if the attack was successful, false otherwise
 */
bool Attacker::tamperMessageTry(
    const MessageFormat::MessageParsed &messageParsed) {
  if (messageParsed._url.size() == 0 || messageParsed._msg.size() == 0 ||
      messageParsed._mac.size() == 0) {
    const std::string errorMessage =
        "Attacker log | messageParsed empty as an input field at the method "
        "Attacker::tamperMessageTry";
    throw std::invalid_argument(errorMessage);
  }
  const unsigned int maxKeySize{64};
  unsigned int keyLength, keyLengthFixed{0};
  const std::string appendMessageGoal{"&admin=true"};
  const std::vector<unsigned char> appendMessageGoalV(appendMessageGoal.begin(),
                                                      appendMessageGoal.end());
  std::vector<unsigned char> messagePadded, newMessage, macByteFormat, newMac;
  std::string tamperedMessage{};
  const char dummyChar = '#';
  MD4InternalState::MD4InternalState md4InternalState;
  // calculation of the new MAC
  // conversion hex to bytes of the mac
  macByteFormat = MessageExtractionFacility::hexToBytes(messageParsed._mac);
  if (Attacker::_debugFlag) {
    std::cout << "\nAttacker log | Size of the mac = " << macByteFormat.size()
              << " bytes" << std::endl;
  }
  // extraction of the internal state of the MD4 of the current mac
  md4InternalState = Attacker::extractionMD4InternalState(macByteFormat);
  // Trial and error to find the length of private key of the server
  for (keyLength = 1; keyLength <= maxKeySize; ++keyLength) {
    std::string keyAndMessage(keyLength, dummyChar);
    bool serverReply{false};
    keyAndMessage += messageParsed._msg;
    messagePadded = Attacker::computeMD4padding(keyAndMessage);
    // Computation of the new MAC using MD4’s state from the intercepted
    // message
    newMac = _md4->hash(appendMessageGoalV, md4InternalState._internalState[0],
                        md4InternalState._internalState[1],
                        md4InternalState._internalState[2],
                        md4InternalState._internalState[3],
                        messagePadded.size() + appendMessageGoalV.size());
    // construction of new forged message:   msg || padding || forged msg
    newMessage.clear();
    newMessage.assign(messagePadded.begin() + keyLength, messagePadded.end());
    newMessage.insert(newMessage.end(), appendMessageGoalV.begin(),
                      appendMessageGoalV.end());
    // Test the keyLength in the server
    serverReply = Attacker::_server->validateMac(newMessage, newMac);
    if (Attacker::_debugFlag) {
      std::cout << "For key length: " << keyLength
                << " server reply: " << serverReply << std::endl;
    }
    if (serverReply) {
      if (Attacker::_debugFlag) {
        std::cout << "\nAttacker log | Size of the server key = " << keyLength
                  << " bytes" << std::endl;
      }
      keyLengthFixed = keyLength;
      tamperedMessage.assign(newMessage.begin(), newMessage.end());
      break;
    }
  }
  if (keyLengthFixed) {
    if (Attacker::_debugFlag) {
      std::cout << "\nAttacker log | Size of the server key = " << keyLength
                << " bytes" << " |\nTampered message: '";
      for (std::size_t i = 0; i < tamperedMessage.size(); ++i) {
        if (i < messageParsed._msg.size() ||
            i > messagePadded.size() - keyLengthFixed - 1) {
          printf("%c", static_cast<unsigned char>(tamperedMessage[i]));
        } else if (i == messagePadded.size() - keyLengthFixed - 1) {
          printf(" x%02x ", static_cast<unsigned char>(tamperedMessage[i]));
        } else {
          printf(" x%02x", static_cast<unsigned char>(tamperedMessage[i]));
        }
      }
      std::cout << "' |\nNew MAC = "
                << MessageExtractionFacility::toHexString(newMac) << std::endl;
    }
    return true;
  }
  return false;
}
/******************************************************************************/