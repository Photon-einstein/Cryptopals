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

const unsigned int blockSize = 16;

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the padding using PKCS#7 format, in the end it will return
the padding result by reference in the v vector and by value true if all ok or
false otherwise */
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

/* this function makes the unpadding using PKCS#7 format, in the end it will return
the unpadding result by reference in the v vector and by value true if all ok or
false otherwise */
bool unpadPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string s = "YELLOW SUBMARINE", sMem;
  std::vector<unsigned char> sV;
  bool b;
  int i;
  sMem = s;
  convertStringToVectorBytes(s, sV);
  b = padPKCS_7(sV, blockSize);
  if (b == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    exit(1);
  }
  convertVectorBytesToString(sV, s);
  std::cout<<"\nPadded version of the string '"<<sMem<<"' using blockSize = "<<
    blockSize<<" is (hex|ascii):\n'";
  for (i = 0; i < sV.size(); ++i) {
    printf("%.2x|%c ", sV[i], sV[i]);
  }
  std::cout<<"\n"<<std::endl;
  b = unpadPKCS_7(sV, blockSize);
  if (b == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    exit(1);
  }
  std::cout<<"Unpadded version of the string '"<<sMem<<"' using blockSize = "<<
    blockSize<<" is (hex|ascii):\n'";
  for (i = 0; i < sV.size(); ++i) {
    printf("%.2x|%c ", sV[i], sV[i]);
  }
  std::cout<<std::endl;
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v) {
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
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s) {
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
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize) {
  if (blockSize <= 0 && blockSize > 255) {
    return false;
  }
  int i, padSize = blockSize - (v.size()%blockSize);
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
bool unpadPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize) {
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
