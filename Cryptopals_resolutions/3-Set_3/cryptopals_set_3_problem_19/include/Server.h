#ifndef SERVER_H
#define SERVER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

class Server {
public:
    /* constructor / destructor*/
    Server(const std::string inputFilePath);
    ~Server();

    /* this function does the decryption of aes-ctr mode, in the end it returns
    the decrypted text and sets flag b by reference to true if no errors or to
    false otherwise */
    std::string decryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
      bool *b);

    /* this function does the encryption of aes-ctr mode, in the end it returns
    the encrypted text and sets flag b by reference to true if no errors or to
    false otherwise */
    std::string encryption(const std::vector<unsigned char> &plaintextBytesAsciiFullText,
        bool *b);

    /* this function does the encryption of aes-ctr mode using the iv and key values,
    in the end it returns the encrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCtrEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
      bool *b);

    /* this function does the decryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCtrDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
      bool *b);

    /* this function will encrypt all the inputs already storead into the vector
    _stringsEncryptedAscii, the counter in the CTR mode will be reset after each
    encryption */
    bool encryptInputs();

    void handleErrors(void);

    int aesCtrEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int aesCtrDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    /* this function will test if the vector decryptedTextV contains the same
    content up to strings of size sizeMaxString, having as reference the vector
    _stringsAscii, it will return true if they have the same content or false
    otherwise */
    bool testDecryptedVectorString(std::vector<std::string> decryptedTextV, const int sizeMaxString);

    /* getter */
    std::vector<unsigned char> getLineReadInAscii();

    std::vector<std::string> getStringsAsciiEncrypted();

private:

  /* this function loads the input string from the file 'inputFilePath' into
  the vector strings, in the end it just returns */
  void loadInputStrings(const std::string inputFilePath);

  /* this function will update the iv vector in the counter mode encryption mode,
  updating the counter and the nonce accordingly */
  void updateIVCtrMode();

  /* this function will reset the iv vector in the counter mode encryption mode,
  reseting the counter accordingly */
  void resetIVCtrMode();

  /* setter */
  void setBlockSize(int blockSize);
  void setKey(const int blockSize);
  void setIV(const int blockSize);

  /* getters */
  int getBlockSize();
  unsigned char* getKey();
  unsigned char* getIV();

private:
  int _blockSize;
  unsigned char *_key = nullptr;
  unsigned char *_iv = nullptr;
  std::vector<unsigned char> _ivV;
  std::vector<std::string> _stringsBase64;
  std::vector<std::string> _stringsAscii;
  std::vector<std::string> _stringsEncryptedAscii;
  unsigned long long int _ctrCounter=0;
  unsigned long long int nonce;
  bool _firstIv=true;
};

#endif
