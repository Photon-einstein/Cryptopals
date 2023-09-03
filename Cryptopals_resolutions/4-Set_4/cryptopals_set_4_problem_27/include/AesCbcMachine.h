#ifndef AES_CBC_MACHINE_H
#define AES_CBC_MACHINE_H

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

class AesCbcMachine {
public:
    /* constructor / destructor*/
    AesCbcMachine(const int blockSize, const std::shared_ptr<Pad>& pad);
    ~AesCbcMachine();

    /* public methods */

    /* this function does the encryption of aes-ecb mode, in the end it returns
    the encrypted text and sets flag b by reference to true if no errors or to
    false otherwise */
    std::string encryption(std::vector<unsigned char> &plaintextBytesAsciiFullText,
      bool *b);

    /* this function does the decryption of aes-ecb mode, in the end it returns
    the decrypted text and sets flag b by reference to true if no errors or to
    false otherwise */
    std::string decryption(std::vector<unsigned char> &encryptedBytesAsciiFullText,
        bool *b);

    /* this function does the encryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
      bool *b);

    /* this function does the decryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesCbcDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
      bool *b);

    void handleErrors(void);

    int aesCbcEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int aesCbcDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    /* this function should quote out the ";" and "=" characters, and in the end
    return the quoted string  */
    std::string sanitizeString (std::string input);

    /* this function will test if the attackersKey matches the AesCbcMachine key's,
    it will return true if matches and false otherwise */
    bool testKey(std::vector<unsigned char> &attackersKey);

private:

  /* setter */
  void setBlockSize(int blockSize);
  void setPad(const std::shared_ptr<Pad>& pad);
  void setKey(const int blockSize);
  void setIV(const int blockSize);

  /* getters */
  int getBlockSize();
  unsigned char* getKey();
  unsigned char* getIV();


  unsigned int _blockSize;
  std::shared_ptr<Pad> _pad;
  unsigned char *_key;
  bool _keyFlagDefined = false; /* true if key already defined, false otherwise */
  unsigned char *_iv;
};

#endif
