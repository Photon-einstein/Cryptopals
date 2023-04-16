#ifndef FUNCTION_H
#define FUNCTION_H

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
#include <memory>

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const bool debugFlag = false, debugFlagExtreme = false;

namespace Function {

  /* this function makes the conversion from a string into a vector of bytes,
  in the end it just returns*/
  void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

  /* this function makes the fulling of the string s based on the content of the
  vector v */
  void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

};

#endif
