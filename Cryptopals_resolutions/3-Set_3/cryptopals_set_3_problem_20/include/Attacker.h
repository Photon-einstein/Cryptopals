#ifndef ATTACKER_H
#define ATTACKER_H

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

#include "./../include/Server.h"

const int minSizeEncryptionStringNotSetFlag = -1;
const int validKeyPoolSearch = 4;

struct keyId {
  int keyLength;
  double editDistance;

  bool operator < (const struct keyId& k) const {
    return (editDistance < k.editDistance);
  }
};

typedef struct {
  unsigned char charMinDeviation;
  double valMinDeviation;
  double valMaxRatioLettersSpace;
} charXorId;

typedef struct {
  std::vector<unsigned char> lineChangedBinaryEncoded;
  std::vector<unsigned char> lineChangedBinaryDecoded;
  std::string lineChangedBinaryDecodedString;
  charXorId charId;
} lineChangedId;

typedef struct {
  double valMaxRatioLettersSpaceMean;
  int keySize;
  std::vector<unsigned char> key;
} bestKeyId;

const int numberEnglishLetters = 26;

class Attacker {
public:
    /* constructor / destructor*/
    Attacker(std::shared_ptr<Server>& server, const int blockSize);
    ~Attacker();

    /* this function will decrypt the encrypted text that the server hands out
    to the attacker, in the end this function should return the decrypted strings
    up to the minimum size of the pool of ciphertext already calculated previously,
    in the end it will update the vector and return true if all ok or false
    otherwise, it will also pass the key size in the end by reference */
    bool decryptMinSizeEncryptedStrings(std::vector<std::string> &decryptedStrings,
      int *sizeKey);

private:

  /* this function makes fulling of the vector keyL for every length of the key,
  orders the vector in ascending order by the editDistance and returns true if all
  ok, false otherwise */
  bool getKeyLengthProfileSorted(std::vector<unsigned char> &encryptedBytesAsciiFullText,
        std::vector<struct keyId> &keyL, int minKeySizeVal, int maxKeySizeVal);

  /* this function makes the calculation of the hamming distance between v1 and
  v2, if there is an error it returns b = false, true otherwise by reference */
  int calcHammingDistance(const std::vector<unsigned char> &v1, const
    std::vector<unsigned char> &v2, bool *b);

  /* this function makes the calculation of the bits on in the char c, in the end
  it just returns that number */
  int calcBitsOn(unsigned char c);

  /* this function return the key for this cypertext encryptedBytesAscii, using the
  data provided in the keyL vector, if all goes ok it will return b = true by
  reference, false otherwise */
  std::vector<unsigned char> getKey(std::vector<unsigned char> &encryptedBytesAscii,
      std::vector<struct keyId> &keyL, bool *b);

  /* this function makes the parsing of the cypertext according to the key length,
  in the end it returns the cypertext parsed acording to each byte of the key length,
  if all went well it returns true by reference in b, or false otherwise */
  std::vector<std::vector<unsigned char>> getDataParseInKeySize(std::vector<unsigned char>
      &encryptedBytesAscii, int keySize, bool *b);

  /* this function for a given line in binary, it will do a xor test with a single
  english alphabet character, determine the best fit, based on the max ratio of
  english letters and spaces, and if this is the best fit it will also update
  the structure lineChangedId, in the end it returns true if no error or false
  otherwise */
  bool testCharactersXor(lineChangedId &lineChangedIdData, std::unordered_map<char,
    float> &englishLetterFrequency, std::vector<unsigned char> &lineReadBinary);

  /* setter */
  void setBlockSize(const int blockSize);
  void setServer(std::shared_ptr<Server>& server);

  /* getters */
  /* this function will get the ciphertext from the server, one string from
  encryption */
  std::vector<std::string> getFullCyphertextFromServer();

  /* this function will get the ciphertext from the server, one string from
  encryption */
  void setFullCyphertextFromServer();

  /* this function will calculate the minimum length at the vector of strings
  _fullCiphertextV and update the field _minSizeEncryptionString accordingly */
  void setMinSizeEncryptionString();

  /* this function will fill the vector _encryptedBytesAsciiTrimmedToMinSizeEncryptionString
  from the vector _fullCiphertextV, taken into consideration the value of the
  _minSizeEncryptionString calculated previously */
  void setEncryptedBytesAsciiTrimmedToMinSizeEncryptionString();

  /* this function makes the calculation of the frequency of the characters that
  resulted from the xor, in the end it returns true if no error or false otherwise */
  bool calcFrequencyData(const std::vector<unsigned char> &xorTest, int *freqXorChar);

  /* this function makes the xor calculation of: sRes = s1 xor c, if there is a
  error it returns false */
  void xorFunction(const std::vector<unsigned char> &vS1, const unsigned char c,
      std::vector<unsigned char> &vRes);

  /* this function makes the calculation of the deviation from the english letter
  frequency, and then it returns the deviation and sets flag to true if no error
  or to false if otherwise */
  double deviationCalc(std::unordered_map<char, float> &englishLetterFrequency,
    int *freqXorChar, bool *flag);

  /* this function makes the calculation of the ratio between all the english
  and spaces compared to the length of the message, and sets flag to true if no
  error or to false if otherwise */
  double ratioCalc(const std::vector<unsigned char> &xorTest, bool *flag);

  /* this function makes the decryption of the cypertext using the key to decrypt,
  the encryption & decryption process was a repeated XOR with a given key, if there
  are no errors it will return true, false otherwise */
  bool decryptText(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    const std::vector<unsigned char> &key, std::vector<unsigned char> &decryptedText);

  /* this function will parse the decryptedTextV vector, into strings of up to size
  keyLength, stored at the vector decryptedStrings, in the end the function will
  just return */
  void parseDecryptedStrings(const std::vector<unsigned char> &decryptedTextV,
    std::vector<std::string> &decryptedStrings, const int keyLength);

private:
  int _blockSize;
  std::shared_ptr<Server> _server;
  std::vector<std::string> _fullCiphertextV;
  std::vector<unsigned char> _encryptedBytesAsciiTrimmedToMinSizeEncryptionString;
  int _minSizeEncryptionString = minSizeEncryptionStringNotSetFlag;
  int _minKeySize = 1;
  int _maxKeySize = minSizeEncryptionStringNotSetFlag;
};

#endif
