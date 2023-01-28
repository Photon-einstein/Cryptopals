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

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* this field contains the code to the padding of the ascii to base64, '=' char */
const unsigned int outputPadding = 64;

/* this function does the decode from hexadecimal into bytes, returning the
result in a vector of unsigned char */
std::vector<unsigned char> decodeHexToByte(std::string &s);

/* this function does the print of the vector of bytes into stdout */
void printVectorBytes(const std::vector<unsigned char> &v);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the conversion of a vector of bytes in Ascii into base64,
if there is a problem in the function it return false, otherwise it return true */
bool convertBytesToBase64(const std::vector<unsigned char> &outputBytesAscii, std::vector<unsigned char> &decodeVectorBase64);

int main () {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", stringDecodedBase64;
  const std::string base64Answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  std::vector<unsigned char> outputBytesAscii = decodeHexToByte(s), decodeVectorBase64;
  bool boolean;
  std::cout<<"Ascii text converted: ";
  printVectorBytes(outputBytesAscii);
  boolean = convertBytesToBase64(outputBytesAscii, decodeVectorBase64);
  std::cout<<"Base64 text converted: ";
  printVectorBytes(decodeVectorBase64);
  convertVectorBytesToString(decodeVectorBase64, stringDecodedBase64);
  std::cout<<"Answer string to compare: "<<base64Answer<<" with size = "<<base64Answer.size()<<std::endl;
  std::cout<<"Result string to compare: "<<stringDecodedBase64<<" with size = "<<stringDecodedBase64.size()<<std::endl;
  if (base64Answer == stringDecodedBase64) {
    std::cout<<"Comparation test passed."<<std::endl;
  } else {
    std::cout<<"Comparation test failed."<<std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
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
void printVectorBytes(const std::vector<unsigned char> &v) {
  for (const unsigned char &b : v) {
    printf("%c", (unsigned char)b);
  }
  printf("\n");
  return;
}
/******************************************************************************/
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s) {
  int i, size = v.size();
  for (i = 0; i < size; ++i) {
    s+=v[i];
  }
  return;
}
/******************************************************************************/
bool convertBytesToBase64(const std::vector<unsigned char> &outputBytesAscii, std::vector<unsigned char> &decodeVectorBase64) {
  unsigned char c, nextChar, base64char[4]={0}, dummyChar = 0;
  int i, sizeOutputBytesAscii = outputBytesAscii.size(), counterMode3AsciiToBase64, j;
  for (i = 0; i < sizeOutputBytesAscii; i+=3) {
    /* first octet to base64 char conversion */
    base64char[0] = (outputBytesAscii[i] >> 2) & 0x3f;
    /* second octet to base64 char conversion */
    if (i+1 < sizeOutputBytesAscii) {
      base64char[1] = ((outputBytesAscii[i] & 0x03) << 4) | (outputBytesAscii[i+1] >> 4 & 0x0f);
    } else {
      base64char[1] = ((outputBytesAscii[i] & 0x03) << 4) | (dummyChar >> 4 & 0x0f);
    }
    /* third octet to base64 char conversion */
    if (i+1 < sizeOutputBytesAscii && i+2 < sizeOutputBytesAscii) {
      base64char[2] = ((outputBytesAscii[i+1] & 0x0f) << 2) | (outputBytesAscii[i+2] >> 6 & 0x03);
    } else if (i+1 < sizeOutputBytesAscii) {
      base64char[2] = ((outputBytesAscii[i+1] & 0x0f) << 2) | (dummyChar >> 6 & 0x03);
    } else {
      base64char[2] = outputPadding;
    }
    /* forth octet to base64 char conversion */
    if (i+2 < sizeOutputBytesAscii) {
      base64char[3] = outputBytesAscii[i+2] & 0x3f;
    } else {
      base64char[3] = outputPadding;
    }
      for (j = 0; j < 4; ++j) {
        if (base64char[j] < 64) {
          decodeVectorBase64.emplace_back(base64CharsDecoder[base64char[j]]);
        } else if (base64char[j] == outputPadding) {
          decodeVectorBase64.emplace_back('=');
        } else {
          perror("Index decode overflow.");
          return false;
        }
      }
  }
  return true;
}
/******************************************************************************/
