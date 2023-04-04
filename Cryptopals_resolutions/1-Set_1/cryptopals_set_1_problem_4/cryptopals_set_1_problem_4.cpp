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

typedef struct {
  unsigned char charMinDeviation;
  double valMinDeviation;
  double valMaxRatioLettersSpace;
} charXorId;

typedef struct {
  std::string lineChangedHexEncoded;
  std::vector<unsigned char> lineChangedBinaryEncoded;
  std::vector<unsigned char> lineChangedBinaryDecoded;
  std::string lineChangedBinaryDecodedString;
  int lineNumber; /* 0 unitialized */
  charXorId charId;
} lineChangedId;

const int numberEnglishLetters = 26;
const bool printContentFile = false; /* if true it will print the content of the
                                      "4.txt" file */

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

/* this function makes the calculation of the ratio between all the english
and spaces compared to the length of the message, and sets flag to true if no
error or to false if otherwise */
double ratioCalc(const std::vector<unsigned char> &xorTest, bool *flag);

/* this function for a given line in binary, it will do a xor test with a single
english alphabet character, determine the best fit, based on the least deviation
from the english letter frequency, and if this is the best fit it will also update
the structure lineChangedId, in the end it returns true if no error or false
otherwise */
bool testCharactersXor(lineChangedId &lineChangedIdData, std::unordered_map<char, float>
  &englishLetterFrequency, const std::vector<unsigned char> &lineReadBinary,
  const std::string &lineReadHex, const int lineNumber);

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
  std::ifstream inputFile;
  inputFile.open("cryptopals_set_1_problem_4_dataset.txt", std::ios::in);
  std::string lineReadHex, lineReadBinary;
  std::vector<unsigned char> encryptedBytesAscii;
  lineChangedId lineChangedIdData={};
  int i=1;
  bool b;
  if (!inputFile) {
    perror("File failed to be opened.");
    exit(1);
  } else {
    std::cout<<"The file '4.txt' was sucessfully opened."<<std::endl;
  }
  if (printContentFile == true) {
    std::cout<<"\nFile content:\n"<<std::endl;
  }
  while (inputFile.good() == true) {
    lineReadHex.clear();
    lineReadBinary.clear();
    std::getline(inputFile, lineReadHex);
    encryptedBytesAscii = decodeHexToByte(lineReadHex);
    convertVectorBytesToString(encryptedBytesAscii, lineReadBinary);
    if (printContentFile == true) {
      std::cout<<"File | Hex | line "<<i<<" | "<<lineReadHex<<std::endl;
      std::cout<<"File | Bin | line "<<i<<" | "<<lineReadBinary<<std::endl;
    }
    ++i;
    b = testCharactersXor(lineChangedIdData, englishLetterFrequency, encryptedBytesAscii, lineReadHex, i);
    if (b == false) {
      perror("\nThere was an error in the function 'testCharactersXor'.");
      exit(1);
    }
  }
  inputFile.close();
  std::cout<<"Line changed was line number: "<<lineChangedIdData.lineNumber<<
    " with:\noriginal Hex value | '"<<lineChangedIdData.lineChangedHexEncoded<<
    "'\ndecoded Ascii value | '"<<lineChangedIdData.lineChangedBinaryDecodedString<<
    "'resulted from xor with character '"<<lineChangedIdData.charId.charMinDeviation<<
    "'."<<std::endl;
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
/* this function makes the calculation of the ratio between all the english
and spaces compared to the length of the message, and sets flag to true if no
error or to false if otherwise */
double ratioCalc(const std::vector<unsigned char> &xorTest, bool *flag) {
    if (xorTest.size() == 0) {
      *flag = false;
      return 0;
    }
    int i, size = xorTest.size(), nLettersAndSpaces=0;
    for (i = 0; i < size; ++i) {
      if (xorTest[i] == ' ' || (tolower(xorTest[i]) >= 'a' && tolower(xorTest[i]) <= 'z')) {
        ++nLettersAndSpaces;
      }
    }
    *flag = true;
    return static_cast<double>(nLettersAndSpaces)/size;
}
/******************************************************************************/
/* this function for a given line in binary, it will do a xor test with a single
english alphabet character, determine the best fit, based on the least deviation
from the english letter frequency, and if this is the best fit it will also update
the structure lineChangedId, in the end it returns true if no error or false
otherwise */
bool testCharactersXor(lineChangedId &lineChangedIdData, std::unordered_map<char, float>
  &englishLetterFrequency, const std::vector<unsigned char> &lineReadBinary,
  const std::string &lineReadHex, const int lineNumber) {
    if (lineReadBinary.size() == 0) {
      perror("\nlineReadBinary has size 0, error.");
      return false;
    }
    int i, xorPossibleKeys=pow(2,8);
    bool b;
    double deviation, ratioLetters;
    std::vector<unsigned char> xorTest;
    std::string xorTestString;
    int *freqXorChar = (int*)calloc(numberEnglishLetters, sizeof (int));
    if (freqXorChar == nullptr) {
      perror("\nfreqXorChar calloc failed.");
      return false;
    }
    /* xor test */
    for (i = 0; i < xorPossibleKeys; ++i) {
      /* reset structures */
      xorTest.clear();
      memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
      xorTestString.clear();
      /* xor */
      xorFunction(lineReadBinary, i, xorTest);
      /* calculate frequency data */
      b = calcFrequencyData(xorTest, freqXorChar);
      if (b == false) {
        perror("\nThere was an error in the function 'calcFrequencyData'");
        return false;
      }
      deviation = deviationCalc(englishLetterFrequency, freqXorChar, &b);
      if (b == false) {
        perror("\nThere was an error in the function 'deviationCalc'");
        exit(1);
      }
      ratioLetters = ratioCalc(xorTest, &b);
      if (b == false) {
        perror("\nThere was an error in the function 'ratioCalc'");
        exit(1);
      }
      if (lineChangedIdData.lineNumber == 0 || ratioLetters > lineChangedIdData.charId.valMaxRatioLettersSpace) {
        lineChangedIdData.lineChangedHexEncoded.clear();
        lineChangedIdData.lineChangedHexEncoded = lineReadHex;
        lineChangedIdData.lineChangedBinaryEncoded.clear();
        lineChangedIdData.lineChangedBinaryEncoded = lineReadBinary;
        lineChangedIdData.lineChangedBinaryDecoded.clear();
        lineChangedIdData.lineChangedBinaryDecoded = xorTest;
        lineChangedIdData.lineChangedBinaryDecodedString.clear();
        convertVectorBytesToString(lineChangedIdData.lineChangedBinaryDecoded,
          lineChangedIdData.lineChangedBinaryDecodedString);
        lineChangedIdData.lineNumber = lineNumber;
        lineChangedIdData.charId.valMinDeviation = deviation;
        lineChangedIdData.charId.charMinDeviation = i;
        lineChangedIdData.charId.valMaxRatioLettersSpace = ratioLetters;
        if (printContentFile == true) {
          std::cout<<"\n###Updated line changed was line number: "<<lineChangedIdData.lineNumber<<
            " with:\noriginal Hex value | "<<lineChangedIdData.lineChangedHexEncoded<<
            " and with \ndecoded Ascii value | "<<lineChangedIdData.lineChangedBinaryDecodedString<<
            "\nresulted from xor with character "<<lineChangedIdData.charId.charMinDeviation<<
            ".\n"<<std::endl;
        }
      }
    }
    /* free memory */
    memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
    free(freqXorChar);
    freqXorChar = nullptr;
    /* return no error status */
    return true;
}
/******************************************************************************/
