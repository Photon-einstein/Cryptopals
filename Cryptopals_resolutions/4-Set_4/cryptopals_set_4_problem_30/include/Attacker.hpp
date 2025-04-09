#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/MD4InternalState.hpp"
#include "./../include/MessageFormat.hpp"
#include "./../include/Server.hpp"

#include <memory>

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool debugFlag);
  ~Attacker();

  /**
   * @brief This method will try perform the Length Extension Attack at
   * MD4
   *
   * This method will try to perform the Length Extension Attack at MD4
   *
   * @return A bool value, true if the attack was successful,
   * false otherwise
   */
  bool lengthExtensionAttackAtMD4();

private:
  /**
   * @brief This method will extract the internal state of the MD4
   *
   * This method will extract the internal state of the MD4 from a mac in a
   * byte format input
   *
   * @param macByteFormat The MD4 mac in a byte format
   * @return The internal state of the MD4
   */
  static MD4InternalState::MD4InternalState
  extractionMD4InternalState(const std::vector<unsigned char> &macByteFormat);

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
  bool tamperMessageTry(const MessageFormat::MessageParsed &messageParsed);

  bool _debugFlag{false};
  const bool _debugFlagExtreme{false};
  static const int _md4DigestLength{MD4_DIGEST_LENGTH};
  const std::string _messageLocation{"./../input/intercepted_url.txt"};
  std::shared_ptr<MyCryptoLibrary::MD4> _md4;
  std::shared_ptr<Server> _server;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
