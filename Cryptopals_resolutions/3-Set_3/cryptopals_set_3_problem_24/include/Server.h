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

#include "./../include/MT19937.h"

typedef struct {
  bool useMt19937Flag;
  unsigned int seedMt19937;
} idPossiblePasswordToken;

const bool debugFlag = false;

class Server {
public:
    /* constructor / destructor*/
    Server();
    ~Server();

    /* this function will return true if the vector _mt19937StateVector has the
    same value as the internal state of MT19937 or false otherwise */
    bool checkEqualVectorStateAtServer(const std::vector<std::uint32_t> &_mt19937StateVector);

    /* this function will extract the next 32 bit number from the mt1997 PRNG and
    it will convert that number into a keystream of 8 bit, return those 8 bits */
    unsigned char getNextKeyStream(std::shared_ptr<MT19937> &mt19937);

    /* this function will encrypt a given plaintext, made at the server, using a
    stream cypher based on a MT19937 PRNG, in the end it will return the encrypted
    data in a vector */
    std::vector<unsigned char> encryptWithStreamCypherBasedOnMt19937();

    /* this function will encrypt a given plaintext using a stream cypher based on a
    MT19937 PRNG, in the end it will return the encrypted data in a vector */
    std::vector<unsigned char> encryptWithStreamCypherBasedOnMt19937 (std::string plaintext);

    /* this function will decrypt a given ciphertext that was created with a stream
    cypher based on a MT19937 PRNG, in the end it will return a string with the
    encrypted data in a vector */
    std::string decryptWithStreamCypherBasedOnMt19937(std::vector<unsigned char> ciphertextV);

    /* this function will return a string with a random number of random characters
    as prefix followed by 14 A's */
    std::string getKnownPlaintext();

    /* this function will decide randonly if it will just generate a randon string
    or else it will generate a password token that is the product of an MT19937 PRNG
    seeded with a random seed up to 16 bits */
    std::string generatePossiblePasswordToken();

    /* this function will check if for a given password reset token, if the answer
    given by the attacker were correct or not, if it were correct then it will return
    true, false otherwise */
    bool checkAttackerAnswer(const std::string &passwordToken,
      const idPossiblePasswordToken &idAnswer);

private:

  /* setter */
  void setSeed();

  void setRandomPrefixSize();
  /* getters */

private:
  std::shared_ptr<MT19937> _mt19937_homeMadeEncrypt, _mt19937_homeMadeDecrypt;
  unsigned int _currentSeed;
  const unsigned int _numberOfAsLetters = 14;
  const unsigned int _maxRandomNumberLetters = _numberOfAsLetters*5;
  unsigned int _randomPrefixSize;
  unsigned int _numberLettersEncryptedWithSameSeed = 0;
  const unsigned int _maxCharactersMt19937WithSameSeed = 624;
  std::map<std::string, idPossiblePasswordToken> _mPasswordToken;
};

#endif
