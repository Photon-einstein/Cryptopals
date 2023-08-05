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

  /* this function will recover the plaintext from the server and it will return
  the plaintext string if no error occurred by reference and return true if no
  error occurred, false otherwise */
  bool recoverPlaintextFromServer(std::string &plaintext);

  /* setter */
  void setServer(std::shared_ptr<Server>& server);

private:
  std::shared_ptr<Server> _server;
};

#endif
