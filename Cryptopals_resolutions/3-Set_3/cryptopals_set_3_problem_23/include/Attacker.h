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

  /* this function will ask for the first _internalStateValueSize values, so
  that the attacker can then recover the full state of the MT19937 PRNG, in the
  end the function will only return */
  void extractNumbersFromMt19937HomeMadeBeforeAttack();

  /* this function will reverse this kind of operation:
  Value = ValueBegin XOR ((ValueBegin >> shift)), in the end it will return the
  value of the ValueBegin, starting with the value of value and shift */
  std::uint32_t reverseShiftRightXor(std::uint32_t value, std::uint8_t shift);

  /* this function will reverse this kind of operation:
  Value = ValueBegin XOR ((ValueBegin << shift) & mask), in the end it will return
  the value of the ValueBegin, starting with the value of value, shift and the
  mask */
  std::uint32_t reverseShiftLeftXor(std::uint32_t value, std::uint8_t shift,
      std::uint32_t mask);

  /* this function will recover the complete state of the MT19937 using as input
  the first 624 numbers extracted from the PRNG MT19937, in the end it will
  return true if all went ok or false otherwise */
  bool recoverStateMt19937();

  /* this function will test if the full state recovered in the function
  'Attacker::recoverStateMt19937()' is correct, if yes it will return true, false
  otherwise */
  bool testRecoverStateMt19937();

  /* this function will try to clone the PRNG MT19937, if it succeeds it will
  return true, false otherwise */
  bool cloneMt19937();

  /* setter */
  void setServer(std::shared_ptr<Server>& server);

private:
  std::shared_ptr<Server> _server;
  const unsigned int _l = 18;
  const unsigned int _t = 15;
  const unsigned int _c = 0xefc60000UL;
  const unsigned int _s = 7;
  const unsigned int _b = 0x9d2c5680UL;
  const unsigned int _u = 11;
  const int _internalStateValueSize = 624;
  std::vector<unsigned int> _mt19937Values;
  std::vector<std::uint32_t> _mt19937StateVector;
  std::shared_ptr<MT19937> _mt19937Test;

};

#endif
