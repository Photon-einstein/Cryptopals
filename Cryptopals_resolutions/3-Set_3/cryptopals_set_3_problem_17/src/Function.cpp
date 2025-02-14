#include <algorithm> // for copy() and assign()
#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <iterator> // for back_inserter
#include <map>
#include <math.h>
#include <memory>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

#include "./../include/Function.h"

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void Function::convertStringToVectorBytes(const std::string &s,
                                          std::vector<unsigned char> &v) {
  int i, size = s.size();
  v.clear();
  for (i = 0; i < size; ++i) {
    v.emplace_back(s[i]);
  }
  return;
}
/******************************************************************************/
/* this function makes the fulling of the string s based on the content of the
vector v */
void Function::convertVectorBytesToString(const std::vector<unsigned char> &v,
                                          std::string &s) {
  int i, size = v.size();
  s.clear();
  for (i = 0; i < size; ++i) {
    s += v[i];
  }
  return;
}
/******************************************************************************/
/* this function makes the padding using PKCS#7 format, in the end it will
return the padding result by reference in the v vector and by value true if all
ok or false otherwise */
bool Function::padPKCS_7(std::vector<unsigned char> &v, int blockSize) {
  if (blockSize <= 0 && blockSize > 255) {
    return false;
  }
  int i, padSize = blockSize - (v.size() % blockSize);
  unsigned char c = (unsigned char)padSize;
  for (i = 0; i < padSize; ++i) {
    v.emplace_back(c);
  }
  return true;
}
/******************************************************************************/
/* this function makes the unpadding using PKCS#7 format, in the end it will
return the unpadding result by reference in the v vector and by value true if
all ok or false otherwise */
bool Function::unpadPKCS_7(std::vector<unsigned char> &v, int blockSize) {
  if (v.size() % blockSize != 0 || v[v.size() - 1] > blockSize) {
    return false;
  }
  int i, size = v.size();
  unsigned char lastPadValue = v[v.size() - 1];
  /* validate pad value */
  for (i = size - 1; i > size - lastPadValue - 1; --i) {
    if (v[i] != lastPadValue) {
      return false;
    }
  }
  v.erase(v.begin() + size - lastPadValue, v.begin() + size);
  return true;
}
/******************************************************************************/
/* this function makes the copy of blockSize bytes from the
previousCypherTextPointer into the vector previousCypherText, if all went ok it
will return true, false otherwise */
bool Function::fillVectorFromPointerArray(
    std::vector<unsigned char> &previousCypherText,
    const unsigned char *previousCypherTextPointer,
    const unsigned int blockSize) {
  if (previousCypherTextPointer == nullptr) {
    return false;
  }
  previousCypherText.clear();
  int i;
  for (i = 0; i < (int)blockSize; ++i) {
    previousCypherText.push_back(previousCypherTextPointer[i]);
  }
  return true;
}
/******************************************************************************/
/* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
error it returns false */
bool Function::xorFunction(const std::vector<unsigned char> &vS1,
                           const std::vector<unsigned char> &vS2,
                           std::vector<unsigned char> &vRes) {
  if (vS1.size() != vS2.size()) {
    return false;
  }
  int i, size = vS1.size();
  vRes.clear();
  for (i = 0; i < size; ++i) {
    vRes.push_back(vS1[i] ^ vS2[i]);
  }
  return true;
}
/******************************************************************************/
/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool Function::decodeBase64ToByte(
    const std::vector<unsigned char> &sV,
    std::map<unsigned char, int> &base64IndexMap,
    std::vector<unsigned char> &encryptedBytesAscii) {
  if (sV.size() % 4 != 0) {
    return false;
  }
  int sizeString = sV.size(), i, j, k, validInputLetters = 0;
  int validOutputLetters = 0;
  unsigned char c, mapBase64Index[4] = {0};
  encryptedBytesAscii.clear();
  /* convert from base64 into bytes taking as input 4 base64 chars at each step
   */
  for (i = 0; i < sizeString; i += 4) {
    /* valid letters count, meaning different from '=' base64char */
    for (j = i, validInputLetters = 0; j < i + 4; ++j) {
      if (sV[j] != '=') {
        ++validInputLetters;
      }
    }
    /* convertion from base64 char into index of the base64 alphabet */
    for (j = i, k = 0; j < i + validInputLetters; ++j, ++k) {
      if (debugFlagExtreme == true) {
        printf("\nChar searching in map: %c -> %d", sV[j],
               base64IndexMap[(unsigned char)sV[j]]);
      }
      mapBase64Index[k] = base64IndexMap[(unsigned char)sV[j]];
    }
    if (debugFlagExtreme == true) {
      std::cout << "\nValidInputLetters for : '" << sV[i] << sV[i + 1]
                << sV[i + 2] << sV[i + 3] << "' is " << validInputLetters;
      std::cout << " with mapBase64Index: ";
      for (j = 0; j < 4; ++j) {
        printf("%d ", mapBase64Index[j]);
      }
      std::cout << std::endl;
    }
    /* valid input letters converted to valid output letters */
    validOutputLetters = validInputLetters - 1;
    for (j = 0; j < validOutputLetters; ++j) {
      if (j == 0) {
        /* 765432 | 10 */
        c = ((mapBase64Index[0] & 0x3F) << 2) |
            ((mapBase64Index[1] & 0x3F) >> 4);
      } else if (j == 1) {
        /* 7654 | 3210 */
        c = ((mapBase64Index[1] & 0x3F) << 4) |
            ((mapBase64Index[2] & 0x3F) >> 2);
      } else if (j == 2) {
        /* 76 | 543210 */
        c = ((mapBase64Index[2] & 0x3F) << 6) |
            ((mapBase64Index[3] & 0x3F) >> 0);
      }
      encryptedBytesAscii.emplace_back(c);
    }
  }
  return true;
}
/******************************************************************************/
