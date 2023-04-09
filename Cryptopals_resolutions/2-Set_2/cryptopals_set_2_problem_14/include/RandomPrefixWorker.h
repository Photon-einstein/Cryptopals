#ifndef RANDOM_PREFIX_WORKER_H
#define RANDOM_PREFIX_WORKER_H

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

class RandomPrefixWorker {
public:
    /* constructor / destructor*/
    RandomPrefixWorker(int blockSize, bool debugFlag, bool debugFlagExtreme, std::string key, std::string iv);
    ~RandomPrefixWorker();

    /* this function returns true if the guess of the random prefix size
    is equal to the randomPrefixSize, false otherwise */
    bool testRandomPrefixSize(int randomPrefixSizeGuess);

    /* this function does the encryption of aes-cbc mode using the iv and key values,
    in the end it returns the decrypted text and sets flag b by reference to true if
    no errors or to false otherwise */
    std::string aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText, bool *b);

    /* getters */
    int getBlockSize();
    bool getDebugFlag();
    bool getDebugFlagExtreme();

private:
  /* setters */
  void setRandomPrefixSize();
  void setDebugFlag(bool debugFlag);
  void setDebugFlagExtreme(bool debugFlagExtreme);
  void setKey(std::string key);
  void setIV(std::string iv);

  /* this function generates a random prefix of size _randomPrefixSize and it
  returns a string of that size filled with random data */
  std::vector<unsigned char> generateRandomPrefix();

  unsigned int _blockSize;
  int _randomPrefixSize;
  bool _debugFlag, _debugFlagExtreme;
  unsigned char *_key, *_iv;
};

#endif
