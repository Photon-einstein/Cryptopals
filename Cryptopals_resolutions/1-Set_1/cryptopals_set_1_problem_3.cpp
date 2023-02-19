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

typedef struct {
  unsigned char charMinDeviation;
  double valMinDeviation;
} charXorId;

const int numberEnglishLetters = 26;
const bool printXorStrings = false; /* if true it will print all the test xor
                                       strings into stdout */

/* this function does the decode from hexadecimal into bytes, returning the
result in a vector of unsigned char */
std::vector<unsigned char> decodeHexToByte(std::string &s);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the xor calculation of: sRes = s1 xor c, if there is a
error it returns false */
void xorFunction(const std::vector<unsigned char> &vS1, const unsigned char c,
  std::vector<unsigned char> &vRes);

/* this function makes the calculation of the frequency of the characters that
resulted from the xor, in the end it returns true if no error or false otherwise */
bool calcFrequencyData(const std::vector<unsigned char> &xorTest, int *freqXorChar);

/* this function makes the calculation of the deviation from the english letter
frequency, and then it returns the deviation and sets flag to true if no error
or to false if otherwise */
double deviationCalc(std::unordered_map<char, float> &englishLetterFrequency,
  int *freqXorChar, bool *flag);

int main () {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::unordered_map<char, float> englishLetterFrequency = {{'a',8.2e-2},{'b',1.5e-2},
    {'c',2.8e-2},{'d',4.3e-2},{'e',13.0e-2},{'f',2.2e-2},{'g',2.0e-2},{'h',6.1e-2},
    {'i',7.0e-2},{'j',0.15e-2},{'k',0.77e-2},{'l',4.0e-2},{'m',2.4e-2},{'n',6.7e-2},
    {'o',7.5e-2},{'p',1.9e-2},{'q',0.095e-2},{'r',6.0e-2},{'s',6.3e-2},{'t',9.1e-2},
    {'u',2.8e-2},{'v',0.98e-2},{'w',2.4e-2},{'x',0.15e-2},{'y',2.0e-2},{'z',0.074e-2}};
  std::string sHexEncrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  std::string sBytesEncrypted = "", xorTestString;
  std::vector<unsigned char> encryptedBytesAscii = decodeHexToByte(sHexEncrypted);
  std::vector<unsigned char> xorTest;
  charXorId cId;
  double minDeviation, deviation;
  bool b;
  int xorPossibleKeys = pow(2,8);
  int *freqXorChar = (int*)calloc(numberEnglishLetters, sizeof (int)), i;
  if (freqXorChar == nullptr) {
    perror("\nfreqXorChar calloc failed.");
    exit(1);
  }
  /* charXorId initialization */
  cId.valMinDeviation = INT_MAX;
  /* convertion from vector of bytes to string */
  convertVectorBytesToString(encryptedBytesAscii, sBytesEncrypted);
  std::cout<<"s(hex) = "<<sHexEncrypted<<", s(ascii) = "<<sBytesEncrypted<<"\n"<<std::endl;
  /* xor test */
  for (i = 0; i < xorPossibleKeys; ++i) {
    /* reset structures */
    xorTest.clear();
    memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
    xorTestString.clear();
    /* xor */
    xorFunction(encryptedBytesAscii, i, xorTest);
    /* calculate frequency data */
    b = calcFrequencyData(xorTest, freqXorChar);
    if (b == false) {
      perror("\nThere was an error in the function 'calcFrequencyData'");
      exit(1);
    }
    deviation = deviationCalc(englishLetterFrequency, freqXorChar, &b);
    if (b == false) {
      perror("\nThere was an error in the function 'deviationCalc'");
      exit(1);
    }
    if (deviation < cId.valMinDeviation) {
      cId.valMinDeviation = deviation;
      cId.charMinDeviation = i;
    }
    if (printXorStrings == true) {
      /* convertion from vector of bytes to string */
      convertVectorBytesToString(xorTest, xorTestString);
      std::cout<<"xor with char '"<<(char)(i)<<"' results in string "<<xorTestString<<"."<<std::endl;
    }
  }
  /* reset structures */
  xorTest.clear();
  xorTestString.clear();
  /* get best string available */
  xorFunction(encryptedBytesAscii, cId.charMinDeviation, xorTest);
  convertVectorBytesToString(xorTest, xorTestString);
  std::cout<<"\nMinimum deviation in xor with char '"<<cId.charMinDeviation<<"' results in the string '"<<xorTestString<<"'."<<std::endl;
  /* free memory */
  memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
  free(freqXorChar);
  freqXorChar = nullptr;
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
  s.clear();
  for (i = 0; i < size; ++i) {
    s+=v[i];
  }
  return;
}
/******************************************************************************/
/* this function makes the xor calculation of: sRes = s1 xor c, if there is a
error it returns false */
void xorFunction(const std::vector<unsigned char> &vS1, const unsigned char c,
    std::vector<unsigned char> &vRes) {
  int size = vS1.size(), i;
  for (i = 0; i < size; ++i) {
    vRes.emplace_back(vS1[i]^c);
  }
  return;
}
/******************************************************************************/
/* this function makes the calculation of the frequency of the characters that
resulted from the xor, in the end it returns true if no error or false otherwise */
bool calcFrequencyData(const std::vector<unsigned char> &xorTest, int *freqXorChar) {
  if (freqXorChar == nullptr) {
    return false;
  }
  int i, size = xorTest.size();
  unsigned char testChar;
  for (i = 0; i < size; ++i) {
    testChar = tolower(xorTest[i]);
    if (testChar >= 'a' && testChar <= 'z') {
      ++freqXorChar[testChar-'a'];
    }
  }
  return true;
}
/******************************************************************************/
/* this function makes the calculation of the deviation from the english letter
frequency, and then it returns the deviation and sets flag to true if no error
or to false if otherwise */
double deviationCalc(std::unordered_map<char, float> &englishLetterFrequency,
  int *freqXorChar, bool *flag) {
    if (freqXorChar == nullptr || flag == nullptr) {
      *flag = false;
      return 0;
    }
    int nSamples=0, i;
    double deviation=0;
    for (i = 0; i < numberEnglishLetters; ++i) {
      nSamples+=freqXorChar[i];
    }
    for (i = 0; i < numberEnglishLetters; ++i) {
      deviation+=fabs(static_cast<double>(freqXorChar[i])/nSamples-englishLetterFrequency['a'+i]);
    }
    *flag = true;
    return deviation;
}
/******************************************************************************/
