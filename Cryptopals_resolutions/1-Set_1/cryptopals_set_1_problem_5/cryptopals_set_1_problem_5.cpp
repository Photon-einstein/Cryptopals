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

const char hex_chars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

/* this function makes the xor of the plaintextVectorBytes with the keyBytesVector
and in the end it returns the vector with the cypherText and sets true in the
bool b if all ok, otherwise it sets to false */
std::vector<unsigned char> xorWithCypher(const std::vector<unsigned char>
  &plaintextVectorBytes, const std::vector<unsigned char> &keyBytesVector,
  bool *b);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the conversion of the vector sAscii from Ascii format into
the hexadecimal format, in the vector vHex, in the end it just returns */
void convertVectorBytesToHexadecimal(std::vector<unsigned char> &vAscii, std::vector<unsigned char> &vHex);

int main () {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string plaintextString = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  std::string keyString = "ICE", cypherTextHexEncodedString = "";
  std::string cypherTextHexSolution = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  std::vector<unsigned char> plaintextVectorBytes, keyBytesVector, cypherTextVector;
  std::vector<unsigned char> cypherTextHexEncoded;
  bool b;
  convertStringToVectorBytes(plaintextString, plaintextVectorBytes);
  convertStringToVectorBytes(keyString, keyBytesVector);
  cypherTextVector = xorWithCypher(plaintextVectorBytes, keyBytesVector, &b);
  if (b == false) {
    perror("\nThere was an error in the function 'xorWithCypher'.");
    exit(1);
  }
  convertVectorBytesToHexadecimal(cypherTextVector, cypherTextHexEncoded);
  convertVectorBytesToString(cypherTextHexEncoded, cypherTextHexEncodedString);
  if (cypherTextHexEncodedString != cypherTextHexSolution) {
    std::cout<<"\nCypher text hexadecimal encoded does not match solution.\n"<<
    "This program:\t"<<cypherTextHexEncodedString<<"\n"<<
    "Solution:\t"<<cypherTextHexSolution<<std::endl;
  } else {
    std::cout<<"\nCypher text hexadecimal encoded does match solution.\n"<<
    "This program:\t"<<cypherTextHexEncodedString<<"\n"<<
    "Solution:\t"<<cypherTextHexSolution<<std::endl;
  }
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
  for (i = 0; i < size; ++i) {
    v.emplace_back(s[i]);
  }
  return;
}
/******************************************************************************/
/* this function makes the xor of the plaintextVectorBytes with the keyBytesVector
and in the end it returns the vector with the cypherText and sets true in the
bool b if all ok, otherwise it sets to false */
std::vector<unsigned char> xorWithCypher(const std::vector<unsigned char>
    &plaintextVectorBytes, const std::vector<unsigned char> &keyBytesVector, bool *b) {
  std::vector<unsigned char> cypherTextVector;
  if (keyBytesVector.size() == 0) {
    *b = false;
    return cypherTextVector;
  }
  int i, j, sizePlaintext = plaintextVectorBytes.size(), sizeKey = keyBytesVector.size();
  for(i = 0, j = 0; i < sizePlaintext; ++i, ++j%=sizeKey) {
    cypherTextVector.emplace_back(plaintextVectorBytes[i]^keyBytesVector[j]);
  }
  *b = true;
  return cypherTextVector;
}
/******************************************************************************/
/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s) {
  int i, size = v.size();
  for (i = 0; i < size; ++i) {
    s+=v[i];
  }
  return;
}
/******************************************************************************/
/* this function makes the conversion of the vector sAscii from Ascii format into
the hexadecimal format, in the vector vHex, in the end it just returns */
void convertVectorBytesToHexadecimal(std::vector<unsigned char> &vAscii,
    std::vector<unsigned char> &vHex) {
  int i, size = vAscii.size();
  for (i = 0; i < size; ++i) {
    vHex.emplace_back(hex_chars[ (vAscii[i] & 0xF0) >> 4 ] );
    vHex.emplace_back(hex_chars[ (vAscii[i] & 0x0F) >> 0 ] );
  }
  return;
}
/******************************************************************************/
