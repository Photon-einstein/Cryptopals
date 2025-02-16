#ifndef ATTACKER_H
#define ATTACKER_H

#include "./../include/SHA.hpp"
#include "./../include/SHA1.hpp"
#include "./../include/Server.hpp"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(std::shared_ptr<Server> &server, bool writeToFile);
  ~Attacker();

  /* public methods */
  /* setter */
  /**
   * @brief This method sets the server
   *
   * This method sets the server into the attackers data structure
   *
   * @param server The server shared pointer
   */
  void setServer(std::shared_ptr<Server> &server);

  /**
   * @brief This method will try to tamper a message
   *
   * This method will try to tamper a message intercepted and
   * deceive the server with another message authentication
   * code (MAC)
   *
   * @param messageLocation The location of the message to be
   * tampered
   * @return A bool value, true if the attack was successful,
   * false otherwise
   */
  bool tamperMessageTry(const std::string &messageLocation);

private:
  /**
   * @brief This method extract the message intercepted
   *
   * This method will extract the message intercepted in a
   * bank transaction
   *
   * @return A bool value, true if the attack was successful,
   * false otherwise
   */
  std::string extractMessage(const std::string &messageLocation);

  /**
   * @brief This method converts a vector into a string in hex format
   *
   * This method will convert a vector into a string of hexadecimal
   * characters, padded with zero
   *
   * @param data The vector with chars to be converted
   * @return A string containing the chars with hexadecimal format, zero padded
   */
  std::string toHexString(const std::vector<unsigned char> &data);

  std::shared_ptr<Server> _server;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
  bool _writeToFile;
};

#endif // ATTACKER_HPP
