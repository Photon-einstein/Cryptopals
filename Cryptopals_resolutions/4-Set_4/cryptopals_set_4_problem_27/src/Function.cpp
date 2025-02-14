#include <algorithm> // for copy() and assign()
#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <climits>
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
/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void Function::convertStringToVectorBytes(const std::string &s,
                                          std::vector<unsigned char> &v) {
  int i, size = s.size();
  v.clear();
  for (i = 0; i < size; ++i) {
    v.push_back(s[i]);
  }
  return;
}
/******************************************************************************/
/* this function appends to the back of the vector a copy of blockSize bytes
from the previousCypherTextPointer, into the vector previousCypherText, if all
went ok it will return true, false otherwise */
bool Function::appendToVectorFromPointerArray(
    std::vector<unsigned char> &previousCypherText,
    const unsigned char *previousCypherTextPointer,
    const unsigned int blockSize) {
  if (previousCypherTextPointer == nullptr) {
    perror(
        "Function log | Error when calling the function "
        "'Function::appendToVectorFromPointerArray', null pointer exception.");
    return false;
  }
  int i;
  for (i = 0; i < (int)blockSize; ++i) {
    previousCypherText.push_back(previousCypherTextPointer[i]);
  }
  return true;
}
/******************************************************************************/
/* this function makes the copy of all the bytes from the
previousCypherTextPointer into the vector previousCypherText, if all went ok it
will return true, false otherwise */
bool Function::fillVectorFromPointerArray(
    std::vector<unsigned char> &previousCypherText,
    const unsigned char *previousCypherTextPointer, const int size) {
  if (previousCypherTextPointer == nullptr) {
    perror("Function log | Error when calling the function "
           "'Function::fillVectorFromPointerArray', null pointer exception.");
    return false;
  }
  previousCypherText.clear();
  int i;
  for (i = 0; i < size; ++i) {
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
    perror("Function log | Error when calling the function "
           "'Function::xorFunction', different vector sizes.");
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
