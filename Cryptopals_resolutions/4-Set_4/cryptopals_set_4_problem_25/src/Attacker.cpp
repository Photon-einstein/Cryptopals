#include <chrono>
#include <cmath>
#include <stdexcept>

#include "./../include/Attacker.h"
#include "./../include/Function.h"
#include "./../include/Server.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server> &server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server> &server) { _server = server; }
/******************************************************************************/
/* this function will recover the plaintext from the server and it will return
the plaintext string if no error occurred by reference and return true if no
error occurred, false otherwise */
bool Attacker::recoverPlaintextFromServer(std::string &plaintext) {
  plaintext.clear();
  unsigned int i, size;
  std::string recoveredPlaintext;
  std::vector<unsigned char> ciphertextV, originalCiphertextV;
  bool b;
  ciphertextV = _server->getCiphertext();
  copy(ciphertextV.begin(), ciphertextV.end(),
       back_inserter(originalCiphertextV));
  std::vector<unsigned char> newTextV(ciphertextV.size(), 0);
  b = _server->editCiphertextAPI(ciphertextV, 0, newTextV);
  if (b == false) {
    perror("Error at the function 'Server::editCiphertextAPI'");
    return false;
  }
  size = ciphertextV.size();
  for (i = 0; i < size; ++i) {
    originalCiphertextV[i] = originalCiphertextV[i] ^ ciphertextV[i];
  }
  Function::convertVectorBytesToString(originalCiphertextV, recoveredPlaintext);
  std::cout << "\nAttacker log | recovered plaintext: \n\n'"
            << recoveredPlaintext << "'." << std::endl;
  return _server->testEqualRecoveredPlaintext(recoveredPlaintext);
}
/******************************************************************************/
