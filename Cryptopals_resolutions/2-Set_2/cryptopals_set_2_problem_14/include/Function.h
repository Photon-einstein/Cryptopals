#ifndef FUNCTION_H
#define FUNCTION_H

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
#include <memory>

#include "./../include/RandomPrefixWorker.h"

typedef struct {
  std::vector<unsigned char> cyphertext;
  std::string encryptionMode; /* 'ECB' or 'CBC' */
} oracleID;

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const unsigned int maxBlockSize = 40;
const unsigned int appendBytesNumber = 5; /* number of bytes to add at the beggining and at the end, 'x|Message|x' */
const bool debugFlag = true, debugFlagExtreme = false;

namespace Function {

  /* this function makes the random filling of a key of size = blockSize, in the
  end it returns true if all ok or false otherwise */
  bool keyFilling(const int blockSize, std::string &key);

  /* this function makes the assertion if it is the ECB encryption mode used in
  this setup, if yes then it will set the string encryptionMode to 'ECB', if not
  it will set it to the other mode used, if there was no problem in the function
  it will return true, false otherwise */
  bool encryptionOracleWrapper(const int blockSize, std::string &encryptionMode);

  /* this function reads the data from the file with the name inputFileName, then
  it does the base64 to ascii convertion, afterwards it return the converted data
  in a vector by reference and returns true if all went ok or false otherwise */
  bool getDecodeDataFromFile(const std::string inputFileName,
      std::vector<unsigned char> &inputBytesAsciiFullText);

  /* this function makes the calculation of the block cypher size, and in the end
  it returns the size by refence and returns true if all went of or false
  otherwise, it will set blockCypherSize to -1 if it cannot find the block size */
  bool getBlockCypherSize(int &blockCypherSize);

  /* this function makes the random filling of a plaintex of length = size, in the
  end it returns true if all ok or false otherwise */
  bool plaintextFilling(std::vector<unsigned char> &v, const int size);

  /* this function makes the population of the dictionary, and in the end it
  returns true if no error or false otherwise */
  bool populateDictionary(std::map<std::string, unsigned char> &dictionary,
      const std::vector<unsigned char> &knownStringV, const int blockSize,
      unsigned char *key, unsigned char *iv);

  /* this function makes the decryption of the encryptedTextV content,
  in the end it returns the decryptedText string and
  returns true if all ok or false otherwise */
  bool decryptText(std::vector<unsigned char> &unknownStringV,
  const int blockSize, unsigned char *key, unsigned char *iv,
  std::string &decryptedText, const std::shared_ptr<RandomPrefixWorker>&randomPrefixWork,
  const int sizeRandomPrefixGuess);

  /* this function makes the decryption of the encryptedTextV content, the last
  byte of the block, in the end it updates the decryptedText string and
  returns true if all ok or false otherwise */
  bool decryptTextRound(const std::vector<unsigned char> &knownStringV,
    const std::vector<unsigned char> &encryptedTextV, const int blockSize,
    unsigned char *keyV, unsigned char *iv, std::string &decryptedText);

  /* this function makes the test if v1 and  v2 are equal considering the search
  size as sizeSearch, it returns true the vectors are equal, false otherwise, it
  will also set the flagWithoutError to true if no errors, false otherwise */
  bool testEqualVectors(std::vector<unsigned char> &v1, std::vector<unsigned char>
      &v2, const unsigned int sizeSearch, bool &flagWithoutError);

  /* this function makes the conversion from a string into a vector of bytes,
  in the end it just returns*/
  void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

  /* this function makes the fulling of the string s based on the content of the
  vector v */
  void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

  /* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
  error it returns false */
  bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2,
    std::vector<unsigned char> &vRes);

  void handleErrors(void);

  int aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen, unsigned char *key,
              unsigned char *iv, unsigned char *cyphertext);

  /* this function makes the padding using PKCS#7 format, in the end it will return
  the padding result by reference in the v vector and by value true if all ok or
  false otherwise */
  bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

  /* this function does the encryption of aes-ecb mode using the iv and key values,
  in the end it returns the decrypted text and sets flag b by reference to true if
  no errors or to false otherwise */
  std::string aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
    unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

  /* this function makes the copy of blockSize bytes from the previousCypherTextPointer
  into the vector previousCypherText, if all went ok it will return true, false
  otherwise */
  bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
    const unsigned char *previousCypherTextPointer, const unsigned int blockSize);

  /* this function makes the encryption of the plaintext, returning a oracleID
  struture filled by value, and true by reference if all went ok or false otherwise */
  oracleID encryptionOracle(std::string plaintext, const int blockSize, bool *b);

  /* this function makes the encryption of the plaintext, returning a oracleID
  struture filled by value, and true by reference if all went ok or false otherwise */
  oracleID encryptionOracleWithoutPrefixAndSufix(std::string plaintext, bool *b);

  /* this function makes the guess of the aes mode encryption, between ECB or CBC,
  in the end it returns his guess by value and true by reference if no error was
  detected or false otherwise */
  std::string detector(const std::vector<unsigned char> &cypherText, const int blockSize, bool *b);

  /* this function does the decode from base64 into bytes, returning the
  result in a vector of unsigned char by reference, if all is ok it will be also
  returned true, false otherwise */
  bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
    &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii);

  /* this function makes the calculations used to estimate the size of the random
  prefix, it will inject two plaintext: p1 = '0...0' and p2='0...01' untile the
  encryption of p1 and p2 has the second block equa, so that (r = random prefix byte)
  (p = padding byte):
  encryption1 = [block1] 'r..r0..0' [block2] '0..0' [block3] '0p..p' and
  encryption2 = [block1] 'r..r0..0' [block2] '0..0' [block3] '1p..p'
  in the end it will return the size of the random prefix by reference and true
  if all went ok or false otherwise */
  bool guessSizeRandomPrefix(const std::shared_ptr<RandomPrefixWorker>&randomPrefixWork,
    int &sizeRandomPrefixGuess, const int blockSize);
};

#endif
