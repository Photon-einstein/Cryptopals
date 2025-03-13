#ifndef MESSAGE_FORMAT_HPP
#define MESSAGE_FORMAT_HPP

#include <string>

namespace MessageFormat {
struct MessageParsed {
  std::string url;
  std::string msg;
  std::string mac;
};
}; // namespace MessageFormat

#endif // MESSAGE_FORMAT_HPP
