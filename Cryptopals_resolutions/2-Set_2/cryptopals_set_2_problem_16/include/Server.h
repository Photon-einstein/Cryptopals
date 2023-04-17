#ifndef Server_H
#define Server_H

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
    Server(const std::shared_ptr<Pad>& pad);
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

    int aesEcbEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

    int aesEcbDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext);

    /* this function receives some data, it will prepend with the content
    "comment1=cooking%20MCs;userdata=" and append with the following content
    ";comment2=%20like%20a%20pound%20of%20bacon", it should quote out the ";"
    and "=" characters */
    std::string processInput(std::string data);

    /* this function should quote out the ";" and "=" characters, and in the end
    return the quoted string  */
    std::string sanitizeString (std::string input);

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


  int _blockSize;
  std::shared_ptr<Pad> _pad;
  unsigned char *_key;
  unsigned char *_iv;
};

#endif
