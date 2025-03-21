#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/MessageFormat.hpp"
#include "./../include/SHA.hpp"
#include "./../include/SHA1.hpp"
#include "./../include/SHA1InternalState.hpp"
#include "./../include/Server.hpp"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool debugFlag);
  ~Attacker();

  /**
   * @brief This method will try perform the Length Extension Attack at
   * the SHA1
   *
   * This method will try to perform the Length Extension Attack at the SHA1
   *
   * @return A bool value, true if the attack was successful,
   * false otherwise
   */
  bool lengthExtensionAttackAtSHA1();

  /**
   * @brief This method extracts the message intercepted
   *
   * This method will extract the message intercepted from a given file location
   *
   * @param messageLocation The location of the message to be extracted
   * @return The message intercepted in a string format
   */
  std::string extractMessage(const std::string &messageLocation);

  /**
   * @brief This method will append the padding to the message
   *
   * This method will append the padding to the message according to
   * the requirements of the SHA1 hash
   *
   * @param message The message to be padded
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
   * @return A bool value, true if the attack was successful, false otherwise
   */
  bool tamperMessageTry(MessageFormat::MessageParsed &messageParsed);

private:
  /**
   * @brief This method will extract the internal state of the SHA1
   *
   * This method will extract the internal state of the SHA1 from a mac in a
   * byte format input
   *
   * @param macByteFormat The SHA1 mac in a byte format
   * @return The internal state of the SHA1
   */
  static SHA1InternalState::SHA1InternalState
  extractionSHA1InternalState(const std::vector<unsigned char> &macByteFormat);

  bool _debugFlag{false};
  const bool _debugFlagExtreme{false};
  static const int _sha1DigestLength{SHA_DIGEST_LENGTH};
  const std::string messageLocation{"./../input/intercepted_url.txt"};
  std::shared_ptr<Server> _server;
  std::shared_ptr<MyCryptoLibrary::SHA1> _sha;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
