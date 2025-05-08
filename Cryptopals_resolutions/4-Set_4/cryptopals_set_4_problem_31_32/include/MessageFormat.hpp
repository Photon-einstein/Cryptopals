#ifndef MESSAGE_FORMAT_HPP
#define MESSAGE_FORMAT_HPP

#include <string>

namespace MessageFormat {
struct MessageParsed {
  std::string _url;
  std::string _msg;
  std::string _mac;
};
}; // namespace MessageFormat

#endif // MESSAGE_FORMAT_HPP
