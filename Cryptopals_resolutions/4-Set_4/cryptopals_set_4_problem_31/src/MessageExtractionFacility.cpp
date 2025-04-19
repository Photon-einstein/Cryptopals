#include "./../include/MessageExtractionFacility.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

/**
 * @brief This method parses the message
 *
 * This method will parses the message, extracting url, message and mac fields
 *
 * @return The message parsed
 */
MessageFormat::MessageParsed
MessageExtractionFacility::parseMessage(const std::string &message,
                                        bool debugFlag) {
  if (message.empty()) {
    const std::string errorMessage =
        "MessageExtractionFacility log | message empty at the method "
        "MessageExtractionFacility::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  std::size_t queryPos, macPos;
  std::string baseUrl, query, mac;
  queryPos = message.find("?");
  MessageFormat::MessageParsed msgParsed;
  if (queryPos == std::string::npos) {
    const std::string errorMessage =
        "MessageExtractionFacility log | query message empty at "
        "the method MessageExtractionFacility::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  macPos = message.find("&mac=");
  if (macPos == std::string::npos) {
    const std::string errorMessage =
        "MessageExtractionFacility log | mac not found at the method "
        "MessageExtractionFacility::parseMessage";
    throw std::invalid_argument(errorMessage);
  }
  baseUrl = message.substr(0, queryPos);
  query = message.substr(queryPos + 1, macPos - queryPos - 1);
  mac = message.substr(macPos + 5);
  msgParsed._url = baseUrl;
  msgParsed._msg = query;
  msgParsed._mac = mac;
  if (debugFlag) {
    std::cout << "\nMessageExtractionFacility log | Message Parsed "
                 "content:\nbase url: '"
              << msgParsed._url << "'\nmessage: '" << msgParsed._msg
              << "'\nmac: '" << msgParsed._mac << "'" << std::endl;
  }
  return msgParsed;
}
/******************************************************************************/
/**
 * @brief This method will convert hexadecimal string to a vector of bytes
 *
 * This method will convert hexadecimal string to a vector of bytes, using zero
 * alignment
 *
 * @param hexStr The input to be converted
 *
 * @return The vector of bytes resulting of the conversion
 */
std::vector<unsigned char>
MessageExtractionFacility::hexToBytes(const std::string &hexStr) {
  if (hexStr.length() % 2 != 0) {
    throw std::invalid_argument("Invalid hex string: length must be even.");
  }
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
 * @brief This method converts a vector of bytes into a string in hex format
 *
 * This method will convert a vector of bytes into a string of hexadecimal
 * characters, padded with zero
 *
 * @param data The vector with bytes to be converted
 * @return A string containing the chars with hexadecimal format, zero padded
 */
std::string
MessageExtractionFacility::toHexString(const std::vector<unsigned char> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0'); // Use hex format and pad with zeros
  for (unsigned char byte : data) {
    ss << std::setw(2)
       << static_cast<int>(byte); // Convert to int to print properly
  }
  std::string hexString = "0x" + ss.str();
  return hexString;
}
/******************************************************************************/