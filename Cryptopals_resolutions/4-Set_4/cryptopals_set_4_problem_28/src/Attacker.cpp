#include <fstream>
#include <iostream>
#include <sstream>

#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server> &server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method sets the server
 *
 * This method sets the server into the attackers data structure
 *
 * @param server The server shared pointer
 */
void Attacker::setServer(std::shared_ptr<Server> &server) { _server = server; }
/******************************************************************************/
/**
 * @brief This method will try to tamper a message
 *
 * This method will try to tamper a message intercepted and
 * deceive the server with another message authentication
 * code (MAC)
 *
 * @param messageLocation The location were the message is located
 * @return The content of the message intercepted by the attacker
 */
bool Attacker::tamperMessageTry() {
  const std::string messageLocation{"./../input/transaction_Alice_to_Bob.json"};
  std::string message = Attacker::extractMessage(messageLocation);
  return true;
}
/******************************************************************************/
/**
 * @brief This method extract the message intercepted
 *
 * This method will extract the message intercepted in a
 * bank transaction
 *
 * @return A bool value, true if the attack was successful,
 * false otherwise
 */
std::string Attacker::extractMessage(const std::string &messageLocation) {
  std::ifstream file(messageLocation);
  if (!file) {
    const std::string errorMessage =
        "Attacker log | " + messageLocation + " file not found";
    throw std::invalid_argument(errorMessage);
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string fileContent = buffer.str();
  return fileContent;
}
/******************************************************************************/