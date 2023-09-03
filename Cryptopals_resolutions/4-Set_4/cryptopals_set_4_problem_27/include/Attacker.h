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

  /* public methods */

  /* this function will try to fetch the key from the server, and if succeeds
  then it will return true, false otherwise */
  bool getKeyFromServer();

  /* setter */
  void setServer(std::shared_ptr<Server>& server);

  void setBlockSize(int blockSize);

  /* getter */
  int getBlockSize();

private:
  std::shared_ptr<Server> _server;
  unsigned int _blockSize;
};

#endif
