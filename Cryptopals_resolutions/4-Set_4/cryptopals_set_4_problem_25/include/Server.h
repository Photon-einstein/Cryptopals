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

#include "./../include/AesEcbMachine.h"
#include "./../include/AesCtrMachine.h"

class Server {
public:
    /* constructor / destructor*/
    Server(const std::string inputFilePath, const std::string aesEcbKey);
    ~Server();

    std::vector<unsigned char> getCiphertext();

    /* this function will test if plaintext matches the _plaintextV from the
    server, and it will return if matches, false otherwise */
    bool testRecoveredPlaintext(const std::vector<unsigned char> &plaintextV);

    /* this function will decrypt the ciphertext, replace the plaintext by the
    newText starting at the offset position, and then encrypt again, returning
    the new ciphertext by reference in the same vector ciphertext, if all went
    ok it will return true, false otherwise */
    bool editCiphertextAPI(std::vector<unsigned char> &ciphertextV, unsigned int
      offset, const std::vector<unsigned char> &newTextV);

    /* this function will return true if the attacker returns the same plaintext
    as the server has it in the database, false otherwise */
    bool testEqualRecoveredPlaintext(const std::string plaintextAttacker);

private:

  /* this function does the decode from base64 into bytes, returning the
  result in a vector of unsigned char by reference, if all is ok it will be also
  returned true, false otherwise */
  bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
    &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii);

  /* this function reads the data from the file with the name inputFileName, then
  it does the base64 to ascii convertion, afterwards it fills the converted data
  in a vector _encryptedBytesAscii and returns without crashing if all went ok */
  void getDecodeDataFromFile(const std::string inputFileName);

  /* setter */
  void setBlockSize(int blockSize);

  /* getters */
  int getBlockSize();

private:
  /* this field contains the alphabet of the base64 format */
  const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<unsigned char> _inputBytesAsciiFullTextV; // ciphertext after base64 convertion and before AES-ECB decryption
  std::string _plaintext; // plaintext
  std::vector<unsigned char> _plaintextV; // plaintext
  std::vector<unsigned char> _ciphertextV; // plaintext encrypted with AES-CTR mode
  unsigned int _blockSize;

  std::shared_ptr<AesEcbMachine> _aesEcbMachine;
  std::shared_ptr<AesCtrMachine> _aesCtrMachine;
};

#endif
