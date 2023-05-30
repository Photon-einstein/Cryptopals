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
    Server(int numberTests, int numberSimulationsPerTest);
    ~Server();

    /* this function will run a simulation of the custom and off the shelf
    implementation of the MT19937_H, in the end it will return true if the
    results were equal, or false if not, it will also returnby reference the
    value of the seedUsed */
    bool runSimulation(std::time_t *seedUsed);

    /* this function will run the _numberTests tests and if all the tests pass
    then it will return true, false otherwise */
    bool runTests();

private:

  /* setter */
  void setSeed();
  /* getters */

private:
  std::shared_ptr<MT19937> _mt19937_homeMade;
  std::mt19937 _mt19937_offTheShelf;
  std::time_t _currentSeed;
  int _numberTests;
  int _numberSimulationsPerTest;
  unsigned int _entropy = 1;
};

#endif
