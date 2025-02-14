#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <cstddef>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <math.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

const char hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
const bool debugFlag = false;
const unsigned int blockSize = 16;

typedef struct {
  bool foundFlag;
  std::vector<int> lineNumberV;
} answerId;

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s,
                                std::vector<unsigned char> &v);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v,
                                std::string &s);

/* this function does the decode from hexadecimal into bytes, returning the
result by reference in a vector of unsigned char */
void decodeHexToByte(std::string &s, std::vector<unsigned char> &output);

/* this function makes the test if  there is repetition of the blocks in the
cypertext, of block size, if yes then it will return true, false otherwise,
if there is an error in the function, flag error will be set to true, false
otherwise */
bool testLineForRepeatedEncryption(const std::vector<unsigned char> &asciiLineV,
                                   const unsigned int blockSize,
                                   bool *flagError);

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::ifstream inputFile;
  std::string inputLineHexadecimalFormat;
  std::vector<unsigned char> hexadecimalLineV, asciiLineV;
  int i, lineNumber = 1;
  bool b, ret;
  answerId ans;
  ans.foundFlag = 0;
  /* execution */
  inputFile.open("cryptopals_set_1_problem_8_dataset.txt", std::ios::in);
  if (!inputFile) {
    perror("File failed to be opened.");
    exit(1);
  } else if (debugFlag == true) {
    std::cout << "The file 'cryptopals_set_1_problem_8_dataset.txt' was "
                 "sucessfully opened."
              << std::endl;
  }
  /* data read and conversion to ascii */
  while (inputFile.good() == true) {
    inputLineHexadecimalFormat.clear();
    hexadecimalLineV.clear();
    asciiLineV.clear();
    std::getline(inputFile, inputLineHexadecimalFormat);
    if (inputLineHexadecimalFormat.size() == 0) {
      continue;
    }
    if (debugFlag == true) {
      std::cout << "Line " << lineNumber << " read (hex): \t\t\t"
                << inputLineHexadecimalFormat << std::endl;
    }
    /* string to vector conversion in hexadecimal format */
    convertStringToVectorBytes(inputLineHexadecimalFormat, hexadecimalLineV);
    if (debugFlag == true) {
      std::cout << "Line " << lineNumber << " read (hex)(vector):   \t";
      for (i = 0; i < (int)hexadecimalLineV.size(); ++i) {
        std::cout << hexadecimalLineV[i];
      }
      std::cout << std::endl;
    }
    /* conversion from hexadecimal into string format */
    decodeHexToByte(inputLineHexadecimalFormat, asciiLineV);
    if (debugFlag == true) {
      std::cout << "Line " << lineNumber
                << " read (ascii)(vector), size = " << asciiLineV.size()
                << ":  \t";
      for (i = 0; i < (int)asciiLineV.size(); ++i) {
        printf("%.2x ", asciiLineV[i]);
      }
      std::cout << "\n" << std::endl;
    }
    ret = testLineForRepeatedEncryption(asciiLineV, blockSize, &b);
    if (b == true) {
      perror("There was an error in the function "
             "'testLineForRepeatedEncryption'.");
      exit(1);
    }
    if (ret == true) {
      ans.foundFlag = true;
      ans.lineNumberV.push_back(lineNumber);
    }
    ++lineNumber;
  }
  inputFile.close();
  /* print answer to screen */
  if (ans.foundFlag == true) {
    for (i = 0; i < (int)ans.lineNumberV.size(); ++i) {
      std::cout << "Line " << ans.lineNumberV[i]
                << " encrypted with ECB mode, detected cypertext repetition."
                << std::endl;
    }
  } else {
    std::cout << "No detection of encryption with ECB mode, as no detected "
                 "cyphertext repetion."
              << std::endl;
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
void convertStringToVectorBytes(const std::string &s,
                                std::vector<unsigned char> &v) {
  int i, size = s.size();
  for (i = 0; i < size; ++i) {
    v.emplace_back(s[i]);
  }
  return;
}
/******************************************************************************/
/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v,
                                std::string &s) {
  int i, size = v.size();
  for (i = 0; i < size; ++i) {
    s += v[i];
  }
  return;
}
/******************************************************************************/
/* this function does the decode from hexadecimal into bytes, returning the
result by reference in a vector of unsigned char */
void decodeHexToByte(std::string &s, std::vector<unsigned char> &output) {
  if (s.size() % 2 != 0) {
    /* zero padding */
    s.push_back('0');
  }
  output.clear();
  unsigned char c;
  std::string binary;
  size_t size = s.size(), i;
  for (i = 0; i < size; i += 2) {
    /* extract two characters from hex string */
    binary.clear();
    binary = s.substr(i, 2);
    /* change it into base 16 and typecast as the character */
    c = stoul(binary, nullptr, 16);
    output.emplace_back(c);
  }
  return;
}
/******************************************************************************/
/* this function makes the test if  there is repetition of the blocks in the
cypertext, of block size, if yes then it will return true, false otherwise,
if there is an error in the function, flag error will be set to true, false
otherwise */
bool testLineForRepeatedEncryption(const std::vector<unsigned char> &asciiLineV,
                                   const unsigned int blockSize,
                                   bool *flagError) {
  if (blockSize == 0 || asciiLineV.size() % blockSize != 0) {
    *flagError = true;
    return false;
  }
  int i, j, size = asciiLineV.size(), nBlocks;
  nBlocks = size / blockSize;
  std::set<std::string> s;
  std::string aux;
  for (i = 0; i < nBlocks; ++i) {
    for (j = 0; j < (int)blockSize; ++j) {
      aux.push_back(asciiLineV[i * blockSize + j]);
    }
    s.insert(aux);
    aux.clear();
  }
  /* return value calculation */
  *flagError = false;
  if ((int)s.size() == nBlocks) {
    return false;
  } else {
    return true;
  }
}
/******************************************************************************/
