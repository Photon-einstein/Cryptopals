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

  /**
   * @brief This method will append the padding to the message
   *
   * This method will append the padding according to the requirements
   * of the SHA1 hash
   *
   * @return The message padded
   */
  std::vector<unsigned char> computeSHA1padding(const std::string &message);

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
  bool tamperMessageTry(MessageFormat::MessageParsed &messageParsed);

  const std::string messageLocation{"./../input/intercepted_url.txt"};

private:
  static const bool debugFlag{true};
  std::shared_ptr<Server> _server;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
