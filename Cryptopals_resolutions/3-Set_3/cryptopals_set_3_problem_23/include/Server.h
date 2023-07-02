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

    /* this function will call the _mt19937_homeMade and will extract the next
    number from the PRNG */
    unsigned int extractNumberFromMt19937HomeMade();

    /* this function will return true if the vector _mt19937StateVector has the
    same value as the internal state of MT19937 or false otherwise */
    bool checkEqualVectorStateAtServer(const std::vector<std::uint32_t> &_mt19937StateVector);

private:

  /* setter */
  void setSeed();
  /* getters */


private:
  std::shared_ptr<MT19937> _mt19937_homeMade;
  std::time_t _currentSeed;
};

#endif
