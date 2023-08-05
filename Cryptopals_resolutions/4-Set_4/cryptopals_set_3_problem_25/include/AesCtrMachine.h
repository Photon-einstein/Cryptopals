#ifndef AES_CTR_MACHINE_H
#define AES_CTR_MACHINE_H

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

#include "./../include/AesEcbMachine.h"

class AesCtrMachine {
public:
  /* constructor / destructor*/
  AesCtrMachine(const unsigned int blockSize);
  ~AesCtrMachine();

  /* this function does the encryption of aes-ctr mode, in the end it returns
  the encrypted text and sets flag b by reference to true if no errors or to
  false otherwise */
  std::string encryption(const std::vector<unsigned char> &plaintextBytesAsciiFullText,
      bool *b);

  /* this function does the decryption of aes-ctr mode, in the end it returns
  the decrypted text and sets flag b by reference to true if no errors or to
  false otherwise */
  std::string decryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    bool *b);

  /* this function will update the iv vector in the counter mode encryption mode,
  updating the counter and the nonce accordingly */
  void updateIVCtrMode();

  /* this function will reset the iv vector in the counter mode encryption mode,
  reseting the counter accordingly */
  void resetIVCtrMode();

  /* this function will update the iv vector in the counter mode encryption mode,
  updating the counter from the _savedCtrCounter value */
  void restoreIVCtrMode();

  /* this function will save the value of the _ctrCounter in the auxiliary variable
  _savedCtrCounter */
  void saveIVCtrMode();

  /* this function will save and then update the _ctrCounter from the new value
  passed in the function and then it will update the IV accordingly */
  void setIVCtrMode(unsigned long long int newCtrCounter);

  

private:

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

  void handleErrors(void);

  int aesCtrEncryptWorker(unsigned char *plaintext, int plaintext_len, unsigned char *key,
              unsigned char *iv, unsigned char *ciphertext);

  int aesCtrDecryptWorker(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
              unsigned char *iv, unsigned char *plaintext);

  /* setter */
  void setBlockSize(int blockSize);
  void setKey(const int blockSize);
  void setIV(const int blockSize);

  /* getters */
  int getBlockSize();
  unsigned char* getKey();
  unsigned char* getIV();

private:
  /* this field contains the alphabet of the base64 format */
  const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<unsigned char> _inputBytesAsciiFullTextV;
  std::string _inputBytesAsciiFullTextDecryptedString;
  unsigned int _blockSize;
  unsigned char *_key = nullptr;
  unsigned char *_iv = nullptr;
  std::vector<unsigned char> _ivV;
  unsigned long long int _ctrCounter=0;
  unsigned long long int _savedCtrCounter=0;
  std::vector<unsigned char> _nonceV;
  std::vector<unsigned char> _nonceSaved;

  std::shared_ptr<AesEcbMachine> _aesEcbMachine;
};

#endif
