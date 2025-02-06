#ifndef SERVER_HPP
#define SERVER_HPP

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

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

// Define SHA_DIGEST_LENGTH if it is not defined elsewhere.
// SHA-1 produces a 160-bit (20-byte) digest.
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

class Server {
public:
  /* constructor / destructor*/
  Server();
  ~Server();

  /* public methods */

  /**
   * @brief Calculates the SHA1 hash using the Openssl library
   *
   * This function takes two integers as input and returns their sum.
   *
   * @param inputV The characters to be hashed in a vector format
   * @param description The characters to be hashed in a string format
   * @return The hash SHA1 of the inputV characters
   */
  std::vector<unsigned char> hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
    const std::string &description);

private:
  bool debugFlag = true;
};

#endif // SERVER_HPP
