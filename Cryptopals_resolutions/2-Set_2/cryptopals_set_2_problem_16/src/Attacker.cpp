#include <stdexcept>

#include "./../include/Attacker.h"
#include "./../include/Function.h"
#include "./../include/Server.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server> &server, const int blockSize) {
  Attacker::setBlockSize(blockSize);
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/* setters */
void Attacker::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server> &server) { _server = server; }
/******************************************************************************/
/* this function tries to attack the CBC encryption mode, the goal is to inject
the substring ";admin=true;", it will return by reference true if it was able
to, false otherwise, it will also return true if all ok or false if there was a
problem in the function */
bool Attacker::attackCBCMode(bool *res) {
  if (res == nullptr) {
    perror("\nThere was an error in the function 'attackCBCMode'.");
    return false;
  }
  std::string input, processedInput;
  int i, prefixLength = strlen("comment1=cooking%20MCs;userdata="),
         sizeInjectedText;
  std::string injectedText = ";admin=true;";
  bool flag, veredict;
  /* input prepare */
  for (i = 0; i < 2 * _blockSize; ++i) {
    input += "a";
  }
  flag = _server->processInput(input, processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  /* add content to the second block */
  sizeInjectedText = injectedText.size();
  for (i = 0; i < blockSize - sizeInjectedText; ++i) {
    injectedText.insert(0, "A");
  }
  if (debugFlag == true) {
    std::cout << "Injected text: '" << injectedText << "'" << std::endl;
  }
  /* erase second input block and add content to the second block as well :) */
  for (i = 0; i < _blockSize; ++i) {
    processedInput[prefixLength + i] ^= 'a' ^ injectedText[i];
  }
  flag = _server->testEncryption(processedInput, res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  return true;
}
/******************************************************************************/
