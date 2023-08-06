#include <stdexcept>
#include <chrono>
#include <cmath>

#include "./../include/Server.h"
#include "./../include/Attacker.h"
#include "./../include/Function.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server>& server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {
}
/******************************************************************************/
/* this function tries to attack the CTR encryption mode, the goal is to inject
the substring ";admin=true;", it will return by reference true if it was able to,
false otherwise, it will also return true if all ok or false if there was a
problem in the function */
bool Attacker::attackCtrMode(bool *res) {
  if (res == nullptr) {
    perror("\nThere was an error in the function 'attackCtrMode'.");
    return false;
  }
  std::string input, processedInput;
  unsigned int i, j, prefixLength = strlen("comment1=cooking%20MCs;userdata="), sizeInjectedText;
  std::string injectedText = ";admin=true;";
  bool flag, veredict;
  /* input prepare */
  for (i = 0; i < injectedText.size(); ++i) {
    input+="a";
  }
  flag = _server->processInput(input, processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  /* overwrite content of Encryption(input) to result in injectedText */
  for(i = prefixLength, j=0; i < prefixLength+input.size(); ++i, ++j) {
    processedInput[i]^=input[j]^injectedText[j];
  }
  flag = _server->testEncryption(processedInput, res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  return true;
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server>& server) {
  _server = server;
}
/******************************************************************************/
