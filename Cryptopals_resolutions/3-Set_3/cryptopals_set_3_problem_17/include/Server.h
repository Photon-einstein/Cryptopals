#ifndef SERVER_H
#define SERVER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
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

#include "./../include/Pad.h"

class Server {
public:
    /* constructor / destructor*/
    Server(const std::string inputFilePath, const std::shared_ptr<Pad>& pad);
    ~Server();

    /* this function does the encryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
      unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

    /* this function does the decryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCbcDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
      unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

    void handleErrors(void);

    int aesCbcEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int aesCbcDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    /* this function should select a string from the set of strings stored at
    the server, encrypt and then return by reference the ciphertext and the iv
    used, it should also return also true if all went ok or false otherwise */
    bool encryptionSessionTokenAesCbcMode(std::vector<unsigned char> &ciphertextV, std::vector<unsigned char> &iv);

    /* this function should consume the ciphertext produced by the function
    'encryptionSessionTokenAesCbcMode' decrypt it, check its padding, and return
    true or false depending on whether the padding is valid or not by reference
    in the returnValue, and should return true if all when ok or false otherwise */
    bool decryptAndCheckPaddingInSessionTokenAesCbcMode(const std::vector<unsigned char> ciphertextV, bool *returnValue);

    /* this function makes the test if a possibleSessionToken is in fact present
    in the server, if yes then this function will return true, false otherwise */
    bool checkPresenceOfValidSessionToken(const std::string &possibleSessionToken);

private:

  /* this function loads the input string from the file 'inputFilePath' into
  the vector strings, in the end it just returns */
  void loadInputStrings(const std::string inputFilePath);

  /* setter */
  void setBlockSize(int blockSize);
  void setPad(const std::shared_ptr<Pad>& pad);
  void setKey(const int blockSize);
  void setIV(const int blockSize);

  /* getters */
  int getBlockSize();
  unsigned char* getKey();
  unsigned char* getIV();


public:
  std::shared_ptr<Pad> _pad;
private:
  int _blockSize;
  unsigned char *_key;
  unsigned char *_iv;
  std::vector<unsigned char> _ivV;
  std::vector<std::string> _stringsBase64;
  std::vector<std::string> _stringsAscii;
  std::set<std::string> _stringsSetBase64;
  std::set<std::string> _stringsSetAscii;
};

#endif
