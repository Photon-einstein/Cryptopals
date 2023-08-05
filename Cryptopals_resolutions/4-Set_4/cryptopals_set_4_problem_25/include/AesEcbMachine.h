#ifndef AES_ECB_MACHINE_H
#define AES_ECB_MACHINE_H

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

class AesEcbMachine {
public:
  /* constructor / destructor*/
  AesEcbMachine(const std::string key, const int blockSize);

  ~AesEcbMachine();

  /* this function does the encryption of aes-ctr mode, in the end it returns
  the encrypted text and sets flag b by reference to true if no errors or to
  false otherwise */
  std::string encryption(const std::vector<unsigned char> &plaintextBytesAsciiFullText,
      bool *b);

  /* this function does the decryption of aes-ecb mode, in the end it returns
  the decrypted text and sets flag b by reference to true if no errors or to
  false otherwise */
  std::string decryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    bool *b);

private:

  /* this function does the encryption of aes-ecb mode using the iv and key values,
  in the end it returns the encrypted text and sets flag b by reference to true if
  no errors or to false otherwise */
  std::string aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
    bool *b);

  /* this function does the decryption of aes-ecb mode using the iv and key values,
  in the end it returns the decrypted text and sets flag b by reference to true if
  no errors or to false otherwise */
  std::string aesEcbDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    bool *b);

  void handleErrors(void);

  int aesEcbEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
              unsigned char *iv, unsigned char *ciphertext);

  int aesEcbDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
              unsigned char *iv, unsigned char *plaintext);


  /* setter */
  void setBlockSize(int blockSize);
  void setKey(const int blockSize, const std::string key);
  void setIV(const int blockSize);
  void setAesEcbKey(const std::string aesEcbKey);

  /* getters */
  int getBlockSize();
  unsigned char* getKey();
  unsigned char* getIV();
  std::string getAesEcbKey();

private:

  std::string _aesEcbKey;
  std::vector<unsigned char> _inputBytesAsciiFullTextV;
  std::vector<unsigned char> _outputBytesAsciiFullTextV;
  std::string _outputBytesAsciiFullTextString;
  unsigned int _blockSize;
  unsigned char *_key = nullptr;
  unsigned char *_iv = nullptr;
  std::vector<unsigned char> _ivV;
};

#endif
