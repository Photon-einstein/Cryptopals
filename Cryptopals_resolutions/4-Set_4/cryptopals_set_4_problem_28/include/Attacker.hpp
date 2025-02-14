#ifndef ATTACKER_H
#define ATTACKER_H

#include "./../include/Server.hpp"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(std::shared_ptr<Server> &server);
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
   * @return A bool value, true if the attack was successful,
   * false otherwise
   */
  bool tamperMessageTry();

private:
  std::string extractMessage(const std::string &messageLocation);

  std::shared_ptr<Server> _server;
};

#endif // ATTACKER_HPP
