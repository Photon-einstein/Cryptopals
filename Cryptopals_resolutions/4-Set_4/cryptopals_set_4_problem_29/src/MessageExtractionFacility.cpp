#include "./../include/MessageExtractionFacility.hpp"

#include <iostream>
#include <stdexcept>

/**
 * @brief This method parses the message
 *
 * This method will parses the message,
 * extracting url, message and mac fields
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
  msgParsed.url = baseUrl;
  msgParsed.msg = query;
  msgParsed.mac = mac;
  if (debugFlag) {
    std::cout << "\nMessageExtractionFacility log | Message Parsed "
                 "content:\nbase url: '"
              << msgParsed.url << "'\nmessage: '" << msgParsed.msg
              << "'\nmac: '" << msgParsed.mac << "'" << std::endl;
  }
  return msgParsed;
}
/******************************************************************************/
