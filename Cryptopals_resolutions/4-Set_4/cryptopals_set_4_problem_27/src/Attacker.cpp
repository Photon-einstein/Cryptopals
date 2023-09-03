#include <stdexcept>
#include <chrono>
#include <cmath>

#include "./../include/Server.h"
#include "./../include/Attacker.h"
#include "./../include/Function.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server>& server) {
  Attacker::setServer(server);
  Attacker::setBlockSize(blockSize);
}
/******************************************************************************/
Attacker::~Attacker() {
}
/******************************************************************************/
/* this function will try to fetch the key from the server, and if succeeds
then it will return true, false otherwise */
bool Attacker::getKeyFromServer() {
  std::vector<unsigned char> plainTextBytesAsciiFullTextV, cipherTextV, p1, p3, keyV;
  std::string decryptedText, key, ciphertext;
  unsigned int i, j, numberBlocks = 3;
  bool b;
  unsigned char highAsciiValue = 200;
  for (i = 0; i < numberBlocks; ++i) {
    for(j = 0; j < _blockSize; ++j) {
      plainTextBytesAsciiFullTextV.push_back(highAsciiValue+i);
    }
  }
  b = _server->encryption(plainTextBytesAsciiFullTextV, ciphertext);
  if (b == false) {
    perror("Attacker log | Error when calling the function 'Server::encryption'.");
    return false;
  }
  Function::convertStringToVectorBytes(ciphertext, cipherTextV);
  /* transform the ciphertext C_1, C_2, C_3 into C_1, 0, C_1 */
  for(j = 0; j < _blockSize; ++j) {
    cipherTextV[_blockSize+j] = 0;
  }
  for(j = 0; j < _blockSize; ++j) {
    cipherTextV[2*_blockSize+j] = cipherTextV[j];
  }
  /* send the changed data into the server to decrypt */
  decryptedText = _server->decryptionWithHighOrderCharTest(cipherTextV, &b);
  if (decryptedText.size() < _blockSize*3) {
    /* not able to recover the key */
    return false;
  }
  /* p1 and p3 calc */
  for(i = 0; i < _blockSize; ++i) {
    p1.push_back(decryptedText[i]);
    p3.push_back(decryptedText[i+2*_blockSize]);
  }
  b = Function::xorFunction(p1, p3, keyV);
  if (b == false) {
    return false;
  }
  b = _server->testKey(keyV);
  if (b == true) {
    std::cout<<"Attacker log | Server key recovered: ";
    for (i = 0; i < keyV.size(); ++i) {
      printf("%.2x ", keyV[i]);
    }
    printf("\n");
  } else {
    std::cout<<"Attacker log | Server key not recovered: "<<std::endl;
  }
  return b;
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server>& server) {
  _server = server;
}
/******************************************************************************/
/* setters */
void Attacker::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Attacker log | Bad blockSize: blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
/* getters */
int Attacker::getBlockSize() {
  return _blockSize;
}
/******************************************************************************/
