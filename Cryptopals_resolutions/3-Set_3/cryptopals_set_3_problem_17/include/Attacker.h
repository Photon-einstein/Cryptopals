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

class Attacker {
public:
    /* constructor / destructor*/
    Attacker(std::shared_ptr<Server>& server, const int blockSize);
    ~Attacker();

    /* this function tries to interact with the server by his interface and it
    will then try to decrypt the session token, if sucessfull it will return the
    session token by reference and set returnValue to true, false otherwise, it
    will also return true if all went without errors, false otherwise */
    bool attackCbcBlockCypherMode(std::string &possibleSessionTokenObtained, bool *returnValue);

private:
  /* setter */
  void setBlockSize(const int blockSize);
  void setServer(std::shared_ptr<Server>& server);
  void setIV(std::vector<unsigned char> ivV);


private:
  int _blockSize;
  std::shared_ptr<Server> _server;
  std::vector<unsigned char> _ivV;
  const int numberOfBitsInOneByte=8;
};

#endif
