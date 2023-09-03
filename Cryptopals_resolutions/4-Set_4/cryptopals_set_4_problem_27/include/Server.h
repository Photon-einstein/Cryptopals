#ifndef SERVER_H
#define SERVER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctime>
#include <string.h>
#include <cstring>
#include <string>
#include <math.h>
#include <ctype.h>
#include <assert.h>
#include <vector>
#include <iostream>
#include <cstddef>
#include <unordered_map>
#include <bits/stdc++.h>
#include <cctype>
#include <fstream>
#include <random>
#include <map>
#include <algorithm> // for copy() and assign()
#include <iterator> // for back_inserter
#include <string.h>
#include <string>
#include <memory>
#include <climits>
#include <random>
#include <cstdlib>

#include "./../include/AesCbcMachine.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"

class Server {
public:
  /* constructor / destructor*/
  Server();
  ~Server();

  /* public methods */

  /* this function should quote out the ";" and "=" characters, and in the end
  return the quoted string  */
  std::string sanitizeString (std::string input);

  /* this function will test if the attackersKey matches the AesCbcMachine key's,
  it will return true if matches and false otherwise */
  bool testKey(std::vector<unsigned char> &attackersKeyV);

  /* this function will do the encryption of the plainTextBytesAsciiFullText,
  returning the ciphertext by reference and true if all went ok or false
  otherwise */
  bool encryption(std::vector<unsigned char> &plainTextBytesAsciiFullText,
    std::string &ciphertext);

  /* this function does the decryption of aes-cbc mode, in the end it returns
  the decrypted text if an high order char was detected, and sets flag b by
  reference to true if no errors or to false otherwise */
  std::string decryptionWithHighOrderCharTest(std::vector<unsigned char> &encryptedBytesAsciiFullText,
      bool *b);

private:
  /* this function does the decryption of aes-cbc mode, in the end it returns
  the decrypted text and sets flag b by reference to true if no errors or to
  false otherwise */
  std::string decryption(std::vector<unsigned char> &encryptedBytesAsciiFullText,
      bool *b);

  /* this function will return true if there is a detection of a high order char
  in the plaintext, false otherwise */
  bool checkHighOrderAsciiChar(std::vector<unsigned char> &plaintextV);

  /* setter */
  void setBlockSize(int blockSize);

  /* getters */
  int getBlockSize();

private:
  unsigned int _blockSize;
  std::shared_ptr<Pad> _padPkcs7;
  std::shared_ptr<AesCbcMachine> _aesCbcMachine;
};

#endif
