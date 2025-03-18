#ifndef MESSAGE_EXTRACTION_FACILITY
#define MESSAGE_EXTRACTION_FACILITY

#include "./../include/MessageFormat.hpp"

#include <string>

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

}; // namespace MessageExtractionFacility

#endif // MESSAGE_EXTRACTION_FACILITY_HPP
