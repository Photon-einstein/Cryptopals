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
const bool debugFlag = true, debugFlagExtreme = false;

namespace Function {

  /* this function makes the conversion from a string into a vector of bytes,
  in the end it just returns*/
  void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

  /* this function makes the fulling of the string s based on the content of the
  vector v */
  void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

  /* this function makes the padding using PKCS#7 format, in the end it will return
  the padding result by reference in the v vector and by value true if all ok or
  false otherwise */
  bool padPKCS_7(std::vector<unsigned char> &v, int blockSize);

  /* this function makes the unpadding using PKCS#7 format, in the end it will return
  the unpadding result by reference in the v vector and by value true if all ok or
  false otherwise */
  bool unpadPKCS_7(std::vector<unsigned char> &v, int blockSize);

  /* this function makes the copy of blockSize bytes from the previousCypherTextPointer
  into the vector previousCypherText, if all went ok it will return true, false
  otherwise */
  bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
    const unsigned char *previousCypherTextPointer, const unsigned int blockSize);

  /* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
  error it returns false */
  bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2,
    std::vector<unsigned char> &vRes);

};

#endif
