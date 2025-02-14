#include <chrono>
#include <stdexcept>
#include <thread>

#include "./../include/Function.h"
#include "./../include/Server.h"

/* constructor / destructor */
Server::Server() {
  bool b;
  Server::setBlockSize(blockSize);
  _padPkcs7 = std::make_shared<PadPKCS_7>(blockSize);
  _aesCbcMachine = std::make_shared<AesCbcMachine>(_blockSize, _padPkcs7);
}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
/* this function should quote out the ";" and "=" characters, and in the end
return the quoted string  */
std::string Server::sanitizeString(std::string input) {
  std::string cleanInput, del = "\\";
  int i, size = input.size();
  /* string sanitization */
  for (i = 0; i < size; ++i) {
    if (input[i] != ';' && input[i] != '=') {
      cleanInput += input[i];
    } else {
      cleanInput += del + input[i];
    }
  }
  return cleanInput;
}
/******************************************************************************/
/* this function will test if the attackersKey matches the AesCbcMachine key's,
it will return true if matches and false otherwise */
bool Server::testKey(std::vector<unsigned char> &attackersKeyV) {
  return _aesCbcMachine->testKey(attackersKeyV);
}
/******************************************************************************/
/* this function will do the encryption of the plainTextBytesAsciiFullText,
returning the ciphertext by reference and true if all went ok or false
otherwise */
bool Server::encryption(std::vector<unsigned char> &plainTextBytesAsciiFullText,
                        std::string &ciphertext) {
  bool b;
  ciphertext = _aesCbcMachine->encryption(plainTextBytesAsciiFullText, &b);
  return b;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode, in the end it returns
the decrypted text if an high order char was detected, and sets flag b by
reference to true if no errors or to false otherwise */
std::string Server::decryptionWithHighOrderCharTest(
    std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  std::vector<unsigned char> decryptedTextV;
  if (b == nullptr) {
    perror("Server log | b pointer cannot be null.");
    return decryptedText;
  } else if (encryptedBytesAsciiFullText.size() == 0 ||
             encryptedBytesAsciiFullText.size() % blockSize != 0) {
    perror("Server log | encrypted vector size cannot be zero.");
    *b = false;
    return decryptedText;
  }
  bool flag;
  decryptedText = Server::decryption(encryptedBytesAsciiFullText, &flag);
  *b = flag;
  if (*b == false) {
    perror("Server log | There was a problem in the function "
           "'Server::decryption'.");
    return decryptedText;
  }
  Function::convertStringToVectorBytes(decryptedText, decryptedTextV);
  flag = Server::checkHighOrderAsciiChar(decryptedTextV);
  if (flag == false) {
    /* no errors were detected so we can overwrite the content of decryptedText
     */
    std::cout << "Server log | Erasing content of decrypted text as no high "
                 "order chars were found, size decryptedText = "
              << decryptedTextV.size() << "." << std::endl;
    decryptedText = "";
  }
  return decryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode, in the end it returns
the decrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string
Server::decryption(std::vector<unsigned char> &encryptedBytesAsciiFullText,
                   bool *b) {
  std::string decryptedText;
  std::vector<unsigned char> decryptedTextV;
  if (b == nullptr) {
    perror("Server log | b pointer cannot be null.");
    return decryptedText;
  } else if (encryptedBytesAsciiFullText.size() == 0 ||
             encryptedBytesAsciiFullText.size() % _blockSize != 0) {
    perror("Server log | Ciphertext should not be empty and should be a "
           "multiple of blockSize.");
    *b = false;
    return decryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "Server log | Size ciphertext to decrypt: "
              << encryptedBytesAsciiFullText.size() << "'." << std::endl;
  }
  decryptedText =
      _aesCbcMachine->decryption(encryptedBytesAsciiFullText, &flag);
  /* return final values */
  *b = flag;
  return decryptedText;
}
/******************************************************************************/
/* this function will return true if there is a detection of a high order char
in the plaintext, false otherwise */
bool Server::checkHighOrderAsciiChar(std::vector<unsigned char> &plaintextV) {
  const unsigned char highOrderAsciiCharThreshold = 127;
  unsigned int i, size = plaintextV.size();
  for (i = 0; i < size; ++i) {
    if (plaintextV[i] > highOrderAsciiCharThreshold) {
      return true;
    }
  }
  return false;
}
/******************************************************************************/
/* setters */
void Server::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Server log | Bad blockSize: blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
/* getters */
int Server::getBlockSize() { return _blockSize; }
/******************************************************************************/
