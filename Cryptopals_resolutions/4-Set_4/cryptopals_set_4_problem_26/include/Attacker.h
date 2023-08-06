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

  /* this function tries to attack the CTR encryption mode, the goal is to inject
  the substring ";admin=true;", it will return by reference true if it was able to,
  false otherwise, it will also return true if all ok or false if there was a
  problem in the function */
  bool attackCtrMode(bool *res);

  /* setter */
  void setServer(std::shared_ptr<Server>& server);

private:
  std::shared_ptr<Server> _server;
};

#endif
