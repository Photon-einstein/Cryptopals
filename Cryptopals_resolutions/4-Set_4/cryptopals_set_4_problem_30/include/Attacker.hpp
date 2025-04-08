#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/MessageFormat.hpp"
#include "./../include/Server.hpp"

#include <memory>

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool debugFlag);
  ~Attacker();

private:
  /**
   * @brief This method extracts the message intercepted
   *
   * This method will extract the message intercepted from a given file location
   *
   * @param messageLocation The location of the message to be extracted
   * @return The message intercepted in a string format
   */
  std::string extractMessage(const std::string &messageLocation) const;

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
  computeMD4padding(const std::string &message) const;

  bool _debugFlag{false};
  const bool _debugFlagExtreme{false};
  const std::string _messageLocation{"./../input/intercepted_url.txt"};
  std::shared_ptr<Server> _server;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
