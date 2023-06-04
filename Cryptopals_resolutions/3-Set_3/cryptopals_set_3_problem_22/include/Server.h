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

#include "./../include/MT19937.h"

class Server {
public:
    /* constructor / destructor*/
    Server();
    ~Server();

    /* this function will run a simulation of the custom MT19937 and will perform
    the seed, and afterwards it will return the first number of pseudo random
    number generator */
    unsigned int returnFirst32BitsOfRNG();

    /* this function will return a random delay between 1 and _maxDelay seconds, and
    then it will return this value */
    int getRandomDelay();

private:

  /* setter */
  void setSeed();
  /* getters */

private:
  std::shared_ptr<MT19937> _mt19937_homeMade;
  std::time_t _currentSeed;
  unsigned int _minDelay = 40, _maxDelay = 1000;
};

#endif
