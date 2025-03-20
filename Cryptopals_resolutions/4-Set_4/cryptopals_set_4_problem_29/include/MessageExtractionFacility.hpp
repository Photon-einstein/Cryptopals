#ifndef MESSAGE_EXTRACTION_FACILITY
#define MESSAGE_EXTRACTION_FACILITY

#include "./../include/MessageFormat.hpp"

#include <string>
#include <vector>

namespace MessageExtractionFacility {

/**
 * @brief This method parses the message intercepted
 *
 * This method will parses the message intercepted,
 * extracting url, message and mac fields
 *
 * @return The message parsed
 */
MessageFormat::MessageParsed parseMessage(const std::string &message,
                                          bool debugFlag);

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
std::vector<unsigned char> hexToBytes(const std::string &hexStr);

}; // namespace MessageExtractionFacility

#endif // MESSAGE_EXTRACTION_FACILITY_HPP
