#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/MessageFormat.hpp"
#include "./../include/SHA.hpp"
#include "./../include/SHA1.hpp"
#include "./../include/Server.hpp"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool writeToFile);
  ~Attacker();

  /**
   * @brief This method extracts the message intercepted
   *
   * This method will extract the message intercepted
   *
   * @return The message intercepted in a string format
   */
  static std::string extractMessage(const std::string &messageLocation);

  /**
   * @brief This method parses the message intercepted
   *
   * This method will parses the message intercepted,
   * extracting url, message and mac fields
   *
   * @return The message parsed
   */
  MessageFormat::MessageParsed parseMessage(const std::string &message);

  const std::string messageLocation{"./../input/intercepted_url.txt"};

private:
  static const bool debugFlag{true};
  std::shared_ptr<Server> _server;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
