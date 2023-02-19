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

const char hex_chars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

/* this function does the decode from hexadecimal into bytes, returning the
result in a vector of unsigned char */
std::vector<unsigned char> decodeHexToByte(std::string &s);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the xor calculation of: sRes = s1 xor s2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2, std::vector<unsigned char> &vRes);

/* this function makes the conversion of the vector sAscii from Ascii format into
the hexadecimal format, in the vector vHex, in the end it just returns */
void convertVectorBytesToHexadecimal(std::vector<unsigned char> &vAscii, std::vector<unsigned char> &vHex);

int main () {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string s1 = "1c0111001f010100061a024b53535009181c", s1Ascii;
  std::string s2 = "686974207468652062756c6c277320657965", s2Ascii, sResXorHex;
  std::string resComp = "746865206b696420646f6e277420706c6179";
  std::vector<unsigned char> outputBytesAsciiS1 = decodeHexToByte(s1);
  std::vector<unsigned char> outputBytesAsciiS2 = decodeHexToByte(s2);
  std::vector<unsigned char> vResAscii, vResHex;
  bool b;
  convertVectorBytesToString(outputBytesAsciiS1, s1Ascii);
  convertVectorBytesToString(outputBytesAsciiS2, s2Ascii);
  std::cout<<"s1(hex) = "<<s1<<", s1(ascii) = "<<s1Ascii<<std::endl;
  std::cout<<"s2(hex) = "<<s2<<", s2(ascii) = "<<s2Ascii<<std::endl;
  b = xorFunction(outputBytesAsciiS1, outputBytesAsciiS2, vResAscii);
  if (b == false) {
    perror("There was an error in the function xor.");
    exit(1);
  }
  convertVectorBytesToHexadecimal(vResAscii, vResHex);
  convertVectorBytesToString(vResHex, sResXorHex);
  std::cout<<"sResXorHex = \t"<<sResXorHex<<".\nresComp = \t"<<resComp<<"."<<std::endl;
  if (sResXorHex != resComp) {
    std::cout<<"Comparation test failed"<<std::endl;
  } else {
    std::cout<<"Comparation test passed"<<std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
/* this function does the decode from hexadecimal into bytes, returning the
result in a vector of unsigned char */
std::vector<unsigned char> decodeHexToByte(std::string &s) {
  if (s.size() % 2 != 0) {
    /* zero padding */
    s.push_back('0');
  }
  std::vector<unsigned char> output;
  unsigned char c;
  size_t size = s.size(), i;
  for (i = 0; i < size; i+=2) {
    if (s[i] >= 'a') {
      c = (10+s[i]-'a')*16;
    } else {
      c = (s[i]-'0')*16;
    }
    if (s[i+1] >= 'a') {
      c+= 10+s[i+1]-'a';
    } else {
      c+= s[i+1]-'0';
    }
    output.emplace_back(c);
  }
  return output;
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
/* this function makes the xor calculation of: sRes = s1 xor s2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned
    char> &vS2, std::vector<unsigned char> &vRes) {
  if (vS1.size() != vS2.size()) {
    return false;
  }
  int size = vS1.size(), i;
  for (i = 0; i < size; ++i) {
    vRes.emplace_back(vS1[i]^vS2[i]);
  }
  return true;
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
