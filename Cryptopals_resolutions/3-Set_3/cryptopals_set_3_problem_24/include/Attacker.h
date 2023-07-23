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
#include <array>

#include "./../include/Server.h"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(std::shared_ptr<Server>& server);
  ~Attacker();

  /* setter */
  void setServer(std::shared_ptr<Server>& server);

  /* this function will extract the next 32 bit number from the mt1997 PRNG and
  it will convert that number into a keystream of 8 bit, return those 8 bits */
  unsigned char getNextKeyStream(std::shared_ptr<MT19937> &mt19937);

  /* this function will extract the next 32 bit number from the mt1997 PRNG and
  it will convert that number into a keystream of 8 bit, return those 8 bits */
  unsigned char getNextKeyStream(MT19937 &mt19937);

  /* this function will recover the key by reference used by the server in the
  mt19937 stream cipher, having as input the vector ciphertext, returning true if
  all went ok or false otherwise */
  bool recoverTheKey(const std::vector<unsigned char> &ciphertext, unsigned int
    &seed);

  /* this function will recover the key by reference used by the server in the
  mt19937 stream cipher, asking first to the server for a given ciphertext
  that the attacker knows before hand that it will end in 14 A's,
  this function has as input the vector ciphertext, returning true if all went ok
  or false otherwise */
  bool recoverTheKeyFromTheServer(unsigned int &seed);

  /* this function will perform _Tests amounnt of tests agains the server's
  database, and if it passes all it will return true, false otherwise */
  bool performTestsAgainstServer();

  idPossiblePasswordToken calculatePossiblePasswordResetTokenVeredict
      (const std::string &possiblePasswordResetToken);

private:
  std::shared_ptr<Server> _server;
  std::shared_ptr<MT19937> _mt19937Attacker;
  const unsigned int _maxLengthTry = 624; // more than this value is enougth for the attacker to clone the MT19937 PRNG
  const unsigned int _maxSeed = INT_MAX;
  const unsigned int _lengthStringsA = 14;
  const unsigned int _nTests = 20; // number of tests regarding the password reset token, done agains the server's database
};

#endif
