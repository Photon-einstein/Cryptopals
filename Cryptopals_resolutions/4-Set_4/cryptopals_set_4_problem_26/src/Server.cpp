#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.h"
#include "./../include/Function.h"

/* constructor / destructor */
Server::Server() {
  bool b;
  Server::setBlockSize(blockSize);
  _aesCtrMachine = std::make_shared<AesCtrMachine>(_blockSize);
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
/* this function receives some data, it will prepend with the content
"comment1=cooking%20MCs;userdata=" and append with the following content
";comment2=%20like%20a%20pound%20of%20bacon", it should quote out the ";"
and "=" characters, then it will encrypt that data using AES cbc mode, and return
that data using inputProcessed, it will return true if all ok or false otherwise */
bool Server::processInput(std::string data, std::string &inputProcessed) {
  std::string processedData;
  std::string encryptedString;
  std::vector<unsigned char> plainTextBytesAsciiFullText;
  bool flag;
  /* clear inputProcessed string */
  inputProcessed.clear();
  processedData = "comment1=cooking%20MCs;userdata=";
  std::string dataCleaned = Server::sanitizeString(data);
  processedData+=dataCleaned+";comment2=%20like%20a%20pound%20of%20bacon";
  if (debugFlag == true) {
    std::cout<<"\nServer log | Data: '"<<data<<"' processed becomes: '"<<dataCleaned<<"'."<<std::endl;
    std::cout<<"\nServer log | Processed input: '"<<processedData<<"', size = "<<processedData.size()<<"."<<std::endl;
  }
  Function::convertStringToVectorBytes(processedData, plainTextBytesAsciiFullText);
  _aesCtrMachine->saveIVCtrMode();
  encryptedString = _aesCtrMachine->encryption(plainTextBytesAsciiFullText, &flag);
  if (flag == false) {
    perror("\nThere was an error in the function 'AesCtrMachine::aesCtrEncryption'.");
    return false;
  }
  /* pass data to the call object */
  inputProcessed = encryptedString;
  return true;
}
/******************************************************************************/
/* this function should quote out the ";" and "=" characters, and in the end
return the quoted string  */
std::string Server::sanitizeString (std::string input) {
  std::string cleanInput, del="\\";
  int i, size = input.size();
  /* string sanitization */
  for(i = 0; i < size; ++i) {
    if (input[i] != ';' && input[i] != '=') {
      cleanInput+=input[i];
    } else {
      cleanInput+=del+input[i];
    }
  }
  return cleanInput;
}
/******************************************************************************/
/* this function will decrypt the string using AES CTR mode, then it will
test for the substring ";admin=true", if it finds it will return true by
reference in res or false otherwise. If all went ok it will return true,
false otherwise */
bool Server::testEncryption(const std::string &encryption, bool *res) {
  if (res == nullptr) {
    perror("\nThere was an error in the function 'testEncryption'.");
    return false;
  }
  std::string decryptedText;
  std::vector<unsigned char> encryptedBytesAsciiFullText;
  bool flag;
  size_t found;
  int i;
  Function::convertStringToVectorBytes(encryption, encryptedBytesAsciiFullText);
  _aesCtrMachine->restoreIVCtrMode();
  decryptedText = _aesCtrMachine->decryption(encryptedBytesAsciiFullText, &flag);
  if (flag == false) {
    perror("\nThere was an error in the function 'AesCtrMachinea::decryption'.");
    return false;
  }
  found = decryptedText.find(";admin=true");
  /* passing finals valus to the calling object */
  *res = (found != std::string::npos) ? true : false ;
  std::cout<<"\nServer log | decrypted text: '"<<decryptedText<<".\n"<<std::endl;
  return true;
}
/******************************************************************************/
/* setters */
void Server::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
/* getters */
int Server::getBlockSize() {
  return _blockSize;
}
/******************************************************************************/
