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
#include <sstream>
#include <cmath>
#include <stdexcept>

#include "./../include/Function.h"

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void Function::convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v) {
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
void Function::convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s) {
  int i, size = v.size();
  s.clear();
  for (i = 0; i < size; ++i) {
    s+=v[i];
  }
  return;
}
/******************************************************************************/
/* this function makes the padding using PKCS#7 format, in the end it will return
the padding result by reference in the v vector and by value true if all ok or
false otherwise */
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
/* this function makes the unpadding using PKCS#7 format, in the end it will return
the unpadding result by reference in the v vector and by value true if all ok or
false otherwise */
bool Function::unpadPKCS_7(std::vector<unsigned char> &v, int blockSize) {
  if (v.size() % blockSize != 0 || v[v.size()-1] > blockSize) {
    return false;
  }
  int i, size = v.size();
  unsigned char lastPadValue = v[v.size()-1];
  /* validate pad value */
  for (i = size-1; i > size-lastPadValue-1; --i) {
    if (v[i] != lastPadValue) {
      return false;
    }
  }
  v.erase(v.begin()+size-lastPadValue, v.begin()+size);
  return true;
}
/******************************************************************************/
/* this function makes the copy of blockSize bytes from the previousCypherTextPointer
into the vector previousCypherText, if all went ok it will return true, false
otherwise */
bool Function::fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
  const unsigned char *previousCypherTextPointer, const unsigned int blockSize){
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
bool Function::xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2,
    std::vector<unsigned char> &vRes) {
  if (vS1.size() != vS2.size()) {
    return false;
  }
  int i, size = vS1.size();
  vRes.clear();
  for (i = 0; i < size; ++i) {
    vRes.push_back(vS1[i]^vS2[i]);
  }
  return true;
}
/******************************************************************************/
/* this function tries to attack the CBC encryption mode, the goal is to inject
the substring ";admin=true;", it will return by reference true if it was able to,
false otherwise, it will also return true if all ok or false if there was a
problem in the function */
bool Function::attackCBCMode(std::shared_ptr<Server> &s, const int blockSize, bool *res) {
  if (blockSize < 1) {
    perror("\nThere was an error in the function 'attackCBCMode'.");
    return false;
  }
  std::string input, processedInput;
  int i, prefixLength = strlen("comment1=cooking%20MCs;userdata="), sizeInjectedText;
  std::string injectedText = ";admin=true;";
  bool flag, veredict;
  /* input prepare */
  for (i = 0; i < 2* blockSize; ++i) {
    input+="a";
  }
  flag = s->processInput(input, processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  /* add content to the second block */
  sizeInjectedText = injectedText.size();
  for (i = 0; i < blockSize-sizeInjectedText; ++i) {
    injectedText.insert(0, "A");
  }
  if (debugFlag == true) {
    std::cout<<"Injected text: '"<<injectedText<<"'"<<std::endl;
  }
  /* erase second input block and add content to the second block as well :) */
  for (i = 0; i < blockSize; ++i) {
    processedInput[prefixLength+i]^='a'^injectedText[i];
  }
  flag = s->testEncryption(processedInput, res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
    return false;
  }
  return true;
}
/******************************************************************************/
