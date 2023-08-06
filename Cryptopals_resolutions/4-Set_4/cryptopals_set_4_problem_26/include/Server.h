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

#include "./../include/AesCtrMachine.h"

class Server {
public:
    /* constructor / destructor*/
    Server();
    ~Server();

    /* this function receives some data, it will prepend with the content
    "comment1=cooking%20MCs;userdata=" and append with the following content
    ";comment2=%20like%20a%20pound%20of%20bacon", it should quote out the ";"
    and "=" characters, then it will encrypt that data using AES CTR mode, and return
    that data using inputProcessed, it will return true if all ok or false otherwise */
    bool processInput(std::string data, std::string &inputProcessed);

    /* this function should quote out the ";" and "=" characters, and in the end
    return the quoted string  */
    std::string sanitizeString (std::string input);

    /* this function will decrypt the string using AES CTR mode, then it will
    test for the substring ";admin=true", if it finds it will return true by
    reference in res or false otherwise. If all went ok it will return true,
    false otherwise */
    bool testEncryption(const std::string &encryption, bool *res);

private:
  /* setter */
  void setBlockSize(int blockSize);

  /* getters */
  int getBlockSize();

private:
  unsigned int _blockSize;
  std::shared_ptr<AesCtrMachine> _aesCtrMachine;
};

#endif
