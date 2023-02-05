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

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const bool debugFlag = false;

struct keyId {
  int keyLenght;
  double editDistance;

  bool operator < (const struct keyId& k) const {
    return (editDistance < k.editDistance);
  }

};

const int numberEnglishLetters = 26;
const int minKeySize = 2, maxKeySize = 40;

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

/* this function makes the calculation of the hamming distance between v1 and
v2, if there is an error it returns b = false, true otherwise by reference */
int calcHammingDistance(const std::vector<unsigned char> &v1, const
  std::vector<unsigned char> &v2, bool *b);

/* this function makes the calculation of the bits on in the char c, in the end
it just returns that number */
int calcBitsOn(unsigned char c);

/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
  &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes fulling of the vector keyL for every length of the key,
orders the vector in ascending order by the editDistance and returns true if all
ok, false otherwise */
bool getKeyLengthProfileSorted(std::vector<unsigned char> &encryptedBytesAsciiFullText,
    std::vector<struct keyId> &keyL, int minKeySizeVal, int maxKeySizeVal);

int main () {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::ifstream inputFile;
  inputFile.open("cryptopals_set_1_problem_6_dataset.txt", std::ios::in);
  std::vector<unsigned char> encryptedBytesAsciiFullText, encryptedBytesAscii;
  std::vector<unsigned char> lineReadBase64Vector;
  std::string lineReadBase64, lineReadBinary;
  std::vector<struct keyId> keyL;
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  int i, size;
  bool b;
  if (!inputFile) {
    perror("File failed to be opened.");
    exit(1);
  } else {
    std::cout<<"The file 'cryptopals_set_1_problem_6_dataset.txt' was sucessfully opened."<<std::endl;
  }
  /* base64IndexMap */
  for(i = 0; i < base64CharsDecoder.size(); ++i) {
    base64IndexMap[base64CharsDecoder[i]] = i;
  }
  if (debugFlag == true) {
    for (it = base64IndexMap.begin(); it != base64IndexMap.end(); ++it) {
      std::cout<<it->first<<" - "<<it->second<<std::endl;
    }
  }
  /* data read and conversion to ascii */
  while(inputFile.good() == true) {
    lineReadBase64.clear();
    lineReadBinary.clear();
    lineReadBase64Vector.clear();
    encryptedBytesAscii.clear();
    std::getline(inputFile, lineReadBase64);
    convertStringToVectorBytes(lineReadBase64, lineReadBase64Vector);
    if (debugFlag == true) {
      /* full text print just to check */
      std::cout<<"Input read line in base64 to convert (string):\n'"<<lineReadBase64<<"'"<<std::endl;
      std::cout<<"Input read line in base64 to convert: \n'";
      for (i = 0; i < lineReadBase64Vector.size(); ++i) {
        printf("%c", lineReadBase64Vector[i]);
      }
      printf("'\n");
    }
    b = decodeBase64ToByte(lineReadBase64Vector, base64IndexMap, encryptedBytesAscii);
    if (b == false) {
      perror("There was an error in the function 'decodeBase64ToByte'.");
      exit(1);
    }
    if (debugFlag == true) {
      std::cout<<"Text read line in binary to decrypt:\n'";
      for (i = 0; i < encryptedBytesAscii.size(); ++i) {
        printf("%c ", encryptedBytesAscii[i]);
      }
      printf("'\n");
    }
    /* pass data read line by line into the full vector data */
    size = encryptedBytesAscii.size();
    for(i = 0; i < size; ++i) {
      encryptedBytesAsciiFullText.emplace_back(encryptedBytesAscii[i]);
    }
  }
  if (debugFlag == true) {
    /* full text print just to check */
    std::cout<<"Full text read in hexadecimal to decrypt:\n"<<std::endl;
    for (i = 0; i < encryptedBytesAsciiFullText.size(); ++i) {
      printf("%x ", encryptedBytesAsciiFullText[i]);
    }
    printf("\n\n");
  }
  /* do study of the key length */
  getKeyLengthProfileSorted(encryptedBytesAsciiFullText, keyL, minKeySize, maxKeySize);
  inputFile.close();
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
/* this function makes the calculation of the hamming distance between v1 and
v2, if there is an error it returns b = false, true otherwise by reference */
int calcHammingDistance(const std::vector<unsigned char> &v1, const
  std::vector<unsigned char> &v2, bool *b) {
  if (v1.size() != v2.size()) {
    *b = false;
    return 0;
  }
  std::vector<unsigned char> xorRes;
  int i, size = v1.size(), hammingDistance=0, n;
  for(i = 0; i < size; ++i) {
    xorRes.emplace_back(v1[i]^v2[i]);
    n=calcBitsOn(xorRes[i]);
    hammingDistance+=n;
  }
  *b=true;
  return hammingDistance;
}
/******************************************************************************/
/* this function makes the calculation of the bits on in the char c, in the end
it just returns that number */
int calcBitsOn(unsigned char c) {
  int nBitsOn=0, i, numberBitsOnByte=8;
  for (i = 0; i < numberBitsOnByte; ++i) {
    if (c & 1 == 1) {
      ++nBitsOn;
    }
    c>>=1;
  }
  return nBitsOn;
}
/******************************************************************************/
/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
  &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii) {
  if (sV.size() % 4 != 0) {
    return false;
  }
  int sizeString = sV.size(), i, j, k, validInputLetters=0;
  int validOutputLetters=0;
  unsigned char c, mapBase64Index[4]={0};
  encryptedBytesAscii.clear();
  /* convert from base64 into bytes taking as input 4 base64 chars at each step */
  for (i = 0; i < sizeString; i+=4) {
    /* valid letters count, meaning different from '=' base64char */
    for (j = i, validInputLetters = 0; j < i+4; ++j) {
      if (sV[j] != '=') {
        ++validInputLetters;
      }
    }
    /* convertion from base64 char into index of the base64 alphabet */
    for(j = i, k = 0; j < i+validInputLetters; ++j, ++k) {
      if (debugFlag == true) {
        printf("\nChar searching in map: %c -> %d", sV[j], base64IndexMap[(unsigned char)sV[j]]);
      }
      mapBase64Index[k] = base64IndexMap[(unsigned char)sV[j]];
    }
    if (debugFlag == true) {
      std::cout<<"\nValidInputLetters for : '"<<sV[i]<<sV[i+1]<<sV[i+2]<<sV[i+3]<<"' is "<<validInputLetters;
      std::cout<<" with mapBase64Index: ";
      for (j = 0; j < 4; ++j) {
        printf("%d ", mapBase64Index[j]);
      }
      std::cout<<std::endl;
    }
    /* valid input letters converted to valid output letters */
    validOutputLetters = validInputLetters-1;
    for (j = 0; j < validOutputLetters; ++j) {
      if (j == 0) {
        /* 765432 | 10 */
        c = ( (mapBase64Index[0] & 0x3F) << 2 ) | ( (mapBase64Index[1] & 0x3F) >> 4 );
      } else if (j == 1) {
        /* 7654 | 3210 */
        c = ( (mapBase64Index[1] & 0x3F) << 4 ) | ( (mapBase64Index[2] & 0x3F) >> 2 );
      } else if (j == 2) {
        /* 76 | 543210 */
        c = ( (mapBase64Index[2] & 0x3F) << 6 ) | ( (mapBase64Index[3] & 0x3F) >> 0 );
      }
      encryptedBytesAscii.emplace_back(c);
    }
  }
  return true;
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
/* this function makes fulling of the vector keyL for every length of the key,
orders the vector in ascending order by the editDistance and returns true if all
ok, false otherwise */
bool getKeyLengthProfileSorted(std::vector<unsigned char> &encryptedBytesAsciiFullText,
      std::vector<struct keyId> &keyL, int minKeySizeVal, int maxKeySizeVal) {
    if (minKeySize > maxKeySizeVal || encryptedBytesAsciiFullText.size() == 0) {
      return false;
    }
    int sizeFullText = encryptedBytesAsciiFullText.size(), nSlices, sliceSize, i, j, k;
    std::vector<unsigned char> slice1, slice2;
    unsigned char c1, c2;
    bool b;
    double score;
    std::string s1,s2;
    struct keyId key;
    for (i = minKeySize; i <= maxKeySizeVal; ++i) {
      sliceSize = 2*i;
      nSlices = sizeFullText/sliceSize;
      /* reset key values */
      key.keyLenght = i;
      key.editDistance = 0;
      score = 0;
      for (j = 0; j < nSlices; ++j) {
        /* slices fulling */
        slice1.clear();
        slice2.clear();
        for (k = 0; k < i; ++k) {
          c1 = encryptedBytesAsciiFullText[k+j*sliceSize];
          c2 = encryptedBytesAsciiFullText[k+j*sliceSize+i];
          slice1.emplace_back(c1);
          slice2.emplace_back(c2);
        }
        /* slice calculation */
        convertVectorBytesToString(slice1, s1);
        convertVectorBytesToString(slice2, s2);
        score+=(double)calcHammingDistance(slice1, slice2, &b)/i;
        if (b == false) {
          std::cout<<"There was an error in the function calcHammingDistance."<<std::endl;
          return false;
        }
      }
      /* normalization by the number of slices */
      key.editDistance = score/nSlices;
      /* update keyL vector */
      keyL.emplace_back(key);
    }
    /* sort the keyL vector by the value of editDistance, in ascending order */
    std::sort(keyL.begin(), keyL.end());
    /* print sort vector */
    std::cout<<"\nKeySize and edit distance (Hamming distance) in decreasing order of the second.\n"<<std::endl;
    for (i = 0; i < keyL.size(); ++i) {
      std::cout<<"Keysize = "<<keyL[i].keyLenght<<"\t | \teditDistance = "<<keyL[i].editDistance<<std::endl;
    }
    return true;
}
/******************************************************************************/
