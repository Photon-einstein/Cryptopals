#include <algorithm> // for copy() and assign()
#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <cstddef>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <iterator> // for back_inserter
#include <math.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

// To compile: $ g++ -Wall -std=c++17 cryptopals_set_2_problem_12.cpp -o
// cryptopals_set_2_problem_12 -lcrypto

std::string key;

typedef struct {
  std::vector<unsigned char> cyphertext;
  std::string encryptionMode; /* 'ECB' or 'CBC' */
} oracleID;

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const unsigned int maxBlockSize = 40;
const unsigned int appendBytesNumber =
    5; /* number of bytes to add at the beggining and at the end, 'x|Message|x'
        */
const bool debugFlag = false, debugFlagExtreme = false;

/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize);

/* this function makes the assertion if it is the ECB encryption mode used in
this setup, if yes then it will set the string encryptionMode to 'ECB', if not
it will set it to the other mode used, if there was no problem in the function
it will return true, false otherwise */
bool encryptionOracleWrapper(const int blockSize, std::string &encryptionMode);

/* this function reads the data from the file with the name inputFileName, then
it does the base64 to ascii convertion, afterwards it return the converted data
in a vector by reference and returns true if all went ok or false otherwise */
bool getDecodeDataFromFile(const std::string inputFileName,
                           std::vector<unsigned char> &inputBytesAsciiFullText);

/* this function makes the calculation of the block cypher size, and in the end
it returns the size by refence and returns true if all went of or false
otherwise, it will set blockCypherSize to -1 if it cannot find the block size */
bool getBlockCypherSize(int &blockCypherSize);

/* this function makes the random filling of a plaintex of length = size, in the
end it returns true if all ok or false otherwise */
bool plaintextFilling(std::vector<unsigned char> &v, const int size);

/* this function makes the population of the dictionary, and in the end it
returns true if no error or false otherwise */
bool populateDictionary(std::map<std::string, int> &dictionary,
                        const std::vector<unsigned char> &knownStringV,
                        const int blockSize, unsigned char *key,
                        unsigned char *iv);

/* this function makes the decryption of the encryptedTextV content,
in the end it returns the decryptedText string and
returns true if all ok or false otherwise */
bool decryptText(std::vector<unsigned char> &unknownStringV,
                 const int blockSize, unsigned char *keyV, unsigned char *iv,
                 std::string &decryptedText);

/* this function makes the decryption of the encryptedTextV content, the last
byte of the block, in the end it updates the decryptedText string and
returns true if all ok or false otherwise */
bool decryptTextRound(const std::vector<unsigned char> &knownStringV,
                      const std::vector<unsigned char> &encryptedTextV,
                      const int blockSize, unsigned char *keyV,
                      unsigned char *iv, std::string &decryptedText);

/* this function makes the test if v1 and  v2 are equal considering the search
size as sizeSearch, it returns true the vectors are equal, false otherwise, it
will also set the flagWithoutError to true if no errors, false otherwise */
bool testEqualVectors(std::vector<unsigned char> &v1,
                      std::vector<unsigned char> &v2,
                      const unsigned int sizeSearch, bool &flagWithoutError);

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s,
                                std::vector<unsigned char> &v);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v,
                                std::string &s);

/* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1,
                 const std::vector<unsigned char> &vS2,
                 std::vector<unsigned char> &vRes);

void handleErrors(void);

int aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *cyphertext);

/* this function makes the padding using PKCS#7 format, in the end it will
return the padding result by reference in the v vector and by value true if all
ok or false otherwise */
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

/* this function does the encryption of aes-ecb mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string
aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
                 unsigned int blockSize, unsigned char *key, unsigned char *iv,
                 bool *b);

/* this function makes the copy of blockSize bytes from the
previousCypherTextPointer into the vector previousCypherText, if all went ok it
will return true, false otherwise */
bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
                                const unsigned char *previousCypherTextPointer,
                                const unsigned int blockSize);

/* this function makes the encryption of the plaintext, returning a oracleID
struture filled by value, and true by reference if all went ok or false
otherwise */
oracleID encryptionOracle(std::string plaintext, const int blockSize, bool *b);

/* this function makes the encryption of the plaintext, returning a oracleID
struture filled by value, and true by reference if all went ok or false
otherwise */
oracleID encryptionOracleWithoutPrefixAndSufix(std::string plaintext, bool *b);

/* this function makes the guess of the aes mode encryption, between ECB or CBC,
in the end it returns his guess by value and true by reference if no error was
detected or false otherwise */
std::string detector(const std::vector<unsigned char> &cypherText,
                     const int blockSize, bool *b);

/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV,
                        std::map<unsigned char, int> &base64IndexMap,
                        std::vector<unsigned char> &encryptedBytesAscii);

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  bool flag;
  std::string encryptionMode,
      inputFileName = "cryptopals_set_2_problem_12_dataset.txt";
  std::string encryptedText, decryptedTextString, unknownString;
  std::vector<unsigned char> unknownStringV, knownStringV, plaintextFullVector;
  std::vector<unsigned char> encryptedTextV;
  std::map<std::string, int> dictionary;
  int blockSizeCalculated = 0;
  unsigned char *keyV;
  unsigned char *iv;
  size_t i;
  /* step 1: key generation */
  flag = keyFilling(blockSize);
  if (flag == false) {
    perror("\nThere was an error in the function 'keyFilling'.");
    exit(1);
  }
  /* step 2: assert ECB encryption mode is used */
  flag = encryptionOracleWrapper(blockSize, encryptionMode);
  if (flag == false) {
    perror("There was a problem in the function 'encryptionOracleWrapper'.");
    exit(1);
  } else if (encryptionMode != "ECB") {
    perror("The encryption scheme used is not ECB mode.");
    exit(1);
  } else {
    std::cout << "\nEncryption oracle veredict: 'ECB' encryption mode is being "
                 "used.\n"
              << std::endl;
  }
  /* step 3: read file content and convert to ascii, then return in vector */
  flag = getDecodeDataFromFile(inputFileName, unknownStringV);
  if (flag == false) {
    perror("There was a problem in the function 'getDecodeDataFromFile'.");
    exit(1);
  }
  /* step 4: detect the block size of the block cypher */
  flag = getBlockCypherSize(blockSizeCalculated);
  if (flag == false) {
    perror("There was a problem in the function 'getBlockCypherSize'.");
    exit(1);
  } else if (blockSizeCalculated == -1) {
    printf("The function 'getBlockCypherSize' could not find a valid block "
           "size up to %d bytes.",
           maxBlockSize);
    exit(1);
  } else {
    std::cout << "Block size calculated: " << blockSizeCalculated << " bytes / "
              << blockSizeCalculated * 8 << " bits." << std::endl;
  }
  /* stage 5: get plaintext of size blockSize-1 to start decoding the data */
  flag = plaintextFilling(knownStringV, blockSize - 1);
  if (flag == false) {
    perror("There was a problem in the function 'plaintextFilling'.");
    exit(1);
  }
  /* stage 6: prepare keyV and iv for later on do the
  encrypt: plaintext || unknown-string with random key in the next step */
  keyV = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  iv = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (keyV == nullptr || iv == nullptr) {
    perror("There was a problem in the memory allocation.");
    exit(1);
  }
  for (i = 0; i < key.size(); ++i) {
    keyV[i] = key[i];
  }
  /* stage 7: decrypt text */
  convertVectorBytesToString(unknownStringV, unknownString);
  flag = decryptText(unknownStringV, blockSize, keyV, iv, decryptedTextString);
  if (flag == false) {
    perror("There was a problem in the function 'decryptText'.");
    exit(1);
  }
  std::cout << "\nDecrypted text: \n'" << decryptedTextString << "'."
            << std::endl;
  if (unknownString == decryptedTextString) {
    std::cout << "\n\nECB decryption test passed." << std::endl;
  } else {
    std::cout << "\n\nECB decryption test failed." << std::endl;
  }
  /* free memory */
  free(keyV);
  free(iv);
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize) {
  if (blockSize < 1) {
    return false;
  }
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 25r inclusive
  int i;
  if (debugFlag == true) {
    printf("\nKey generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    key.push_back(dist1(gen));
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)key[i]);
    }
  }
  printf("\n");
  return true;
}
/******************************************************************************/
/* this function makes the assertion if it is the ECB encryption mode used in
this setup, if yes then it will set the string encryptionMode to 'ECB', if not
it will set it to the other mode used, if there was no problem in the function
it will return true, false otherwise */
bool encryptionOracleWrapper(const int blockSize, std::string &encryptionMode) {
  if (blockSize < 1) {
    return false;
  }
  std::string plaintext = "";
  oracleID id;
  bool b;
  int i;
  /* rest of the work */
  for (i = 0; i < (int)blockSize * 2; ++i) {
    plaintext.push_back(0);
  }
  id = encryptionOracle(plaintext, blockSize, &b);
  if (b == false) {
    perror("There was a problem in the function 'encryptionOracle'.");
    return false;
  }
  /* if it reaches here then all went ok */
  encryptionMode = id.encryptionMode;
  return true;
}
/******************************************************************************/
/* this function reads the data from the file with the name inputFileName, then
it does the base64 to ascii convertion, afterwards it return the converted data
in a vector by reference and returns true if all went ok or false otherwise */
bool getDecodeDataFromFile(
    const std::string inputFileName,
    std::vector<unsigned char> &inputBytesAsciiFullText) {
  if (inputFileName.size() == 0) {
    return false;
  }
  std::ifstream inputFile;
  inputFile.open("cryptopals_set_2_problem_12_dataset.txt", std::ios::in);
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  std::vector<unsigned char> inputBytesAscii;
  std::vector<unsigned char> lineReadBase64Vector, lineReadBase64VectorFullText;
  std::string lineReadBase64;
  int i, size;
  bool b;
  /* rest of the work to be done */
  if (!inputFile) {
    perror("File failed to be opened.");
    return false;
  } else if (debugFlagExtreme == true) {
    std::cout << "The file 'cryptopals_set_2_problem_12_dataset.txt' was "
                 "sucessfully opened.\n"
              << std::endl;
  }
  /* base64IndexMap */
  for (i = 0; i < (int)base64CharsDecoder.size(); ++i) {
    base64IndexMap[base64CharsDecoder[i]] = i;
  }
  if (debugFlagExtreme == true) {
    std::cout << "Base 64 dictionary mapping:" << std::endl;
    for (it = base64IndexMap.begin(); it != base64IndexMap.end(); ++it) {
      std::cout << it->first << " - " << it->second << std::endl;
    }
    printf("\n");
  }
  /* data read and conversion to ascii */
  while (inputFile.good() == true) {
    lineReadBase64.clear();
    lineReadBase64Vector.clear();
    inputBytesAscii.clear();
    std::getline(inputFile, lineReadBase64);
    convertStringToVectorBytes(lineReadBase64, lineReadBase64Vector);
    if (debugFlagExtreme == true && lineReadBase64Vector.size() > 0) {
      /* full text print just to check */
      std::cout << "Input read line in base64 to convert (string):\n'"
                << lineReadBase64 << "'" << std::endl;
      std::cout << "Input read line in base64 to convert: \n'";
      for (i = 0; i < (int)lineReadBase64Vector.size(); ++i) {
        printf("%c", lineReadBase64Vector[i]);
      }
      printf("'\n");
    }
    b = decodeBase64ToByte(lineReadBase64Vector, base64IndexMap,
                           inputBytesAscii);
    if (b == false) {
      perror("There was an error in the function 'decodeBase64ToByte'.");
      return false;
    }
    if (debugFlagExtreme == true && inputBytesAscii.size() > 0) {
      std::cout << "Text read line in binary to decrypt:\n'";
      for (i = 0; i < (int)inputBytesAscii.size(); ++i) {
        printf("%.2x ", inputBytesAscii[i]);
      }
      printf("'\n\n");
    }
    /* pass data read line by line into the full vector data */
    size = inputBytesAscii.size();
    for (i = 0; i < size; ++i) {
      inputBytesAsciiFullText.emplace_back(inputBytesAscii[i]);
    }
    /* pass data input data read line by line into the full vector data */
    size = lineReadBase64Vector.size();
    for (i = 0; i < size; ++i) {
      lineReadBase64VectorFullText.emplace_back(lineReadBase64Vector[i]);
    }
  }
  /* print input data if debug flag is on */
  if (debugFlag == true && lineReadBase64VectorFullText.size() > 0) {
    std::cout << "Input text read in base64:\n'";
    for (i = 0; i < (int)lineReadBase64VectorFullText.size(); ++i) {
      printf("%c", lineReadBase64VectorFullText[i]);
      if ((i + 1) % 60 == 0) {
        printf("\n ");
      }
    }
    printf("'\n\n");
  }
  /* print return data if debug flag is on */
  if (debugFlag == true && inputBytesAsciiFullText.size() > 0) {
    std::cout << "Input text read in ascii:\n'";
    for (i = 0; i < (int)inputBytesAsciiFullText.size(); ++i) {
      printf("%.2x ", inputBytesAsciiFullText[i]);
      if ((i + 1) % 60 == 0) {
        printf("\n ");
      }
    }
    printf("'\n\n");
  }
  inputFile.close();
  return true;
}
/******************************************************************************/
/* this function makes the calculation of the block cypher size, and in the end
it returns the size by refence and returns true if all went of or false
otherwise, it will set blockCypherSize to -1 if it cannot find the block size */
bool getBlockCypherSize(int &blockCypherSize) {
  std::vector<unsigned char> previousCypherTextV, cypherTextV;
  int i, maxSize = maxBlockSize;
  std::string plaintext = "A";
  oracleID id;
  bool b, found = false;
  /* previousCypherText initialization */
  id = encryptionOracleWithoutPrefixAndSufix(plaintext, &b);
  if (b == false) {
    perror("There was a problem in the function "
           "'encryptionOracleWithoutPrefixAndSufix'.");
    return false;
  }
  previousCypherTextV = id.cyphertext;
  for (i = 2; i < maxSize; ++i) {
    plaintext += 'A';
    id = encryptionOracleWithoutPrefixAndSufix(plaintext, &b);
    if (b == false) {
      perror("There was a problem in the function "
             "'encryptionOracleWithoutPrefixAndSufix'.");
      return false;
    }
    cypherTextV = id.cyphertext;
    found = testEqualVectors(previousCypherTextV, cypherTextV, i - 1, b);
    if (b == false) {
      perror("There was a problem in the function 'testEqualVectors'.");
      return false;
    } else if (found == true) {
      blockCypherSize = i - 1;
      return true;
    }
    /* vectors update */
    previousCypherTextV.clear();
    previousCypherTextV = cypherTextV;
    cypherTextV.clear();
  }
  /* if it reaches here then it has not found a valid blockCypherSize */
  blockCypherSize = -1;
  return true;
}
/******************************************************************************/
/* this function makes the random filling of a plaintex of length = size, in the
end it returns true if all ok or false otherwise */
bool plaintextFilling(std::vector<unsigned char> &v, const int size) {
  if (blockSize < 1) {
    return false;
  }
  int i;
  if (debugFlag == true) {
    printf("\nPlaintext generated (size: %d): '", size);
  }
  for (i = 0; i < size; ++i) {
    v.push_back('A');
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)v[i]);
    }
  }
  if (debugFlag == true) {
    printf("'\n");
  }
  return true;
}
/******************************************************************************/
/* this function makes the population of the dictionary, and in the end it
returns true if no error or false otherwise */
bool populateDictionary(std::map<std::string, unsigned char> &dictionary,
                        const std::vector<unsigned char> &knownStringV,
                        const int blockSize, unsigned char *key,
                        unsigned char *iv) {
  if ((int)knownStringV.size() != blockSize - 1 || blockSize < 1 ||
      key == nullptr || iv == nullptr) {
    return false;
  }
  int i, j;
  bool b;
  std::string encryptedText, encryptedTextNotPadded;
  std::vector<unsigned char> plaintextV, plaintextVPadded;
  /* clear dictionary */
  dictionary.clear();
  /* plaintextV fulling */
  for (i = 0; i < (int)knownStringV.size(); ++i) {
    plaintextV.push_back(knownStringV[i]);
  }
  /* last byte fulling */
  plaintextV.push_back(0);
  for (i = 0; i < 255; ++i) {
    plaintextV[blockSize - 1] = i;
    /* pass vector to padd afterwars */
    plaintextVPadded.clear();
    copy(plaintextV.begin(), plaintextV.end(), back_inserter(plaintextVPadded));
    b = padPKCS_7(plaintextVPadded, blockSize);
    if (b == false) {
      perror("There was a problem in the function 'padPKCS_7'");
      return false;
    }
    encryptedText = aesEcbEncryption(plaintextVPadded, blockSize, key, iv, &b);
    if (b == false) {
      perror("There was a problem in the function 'aesEcbEncryption'.");
      return false;
    }
    /* update dictionary with the encrypted text and the last byte */
    encryptedTextNotPadded.clear();
    for (j = 0; j < blockSize; ++j) {
      encryptedTextNotPadded += encryptedText[j];
    }
    dictionary[encryptedTextNotPadded] = (unsigned char)i;
  }
  return true;
}
/******************************************************************************/
/* this function makes the decryption of the encryptedTextV content,
in the end it returns the decryptedText string and
returns true if all ok or false otherwise */
bool decryptText(std::vector<unsigned char> &unknownStringV,
                 const int blockSize, unsigned char *keyV, unsigned char *iv,
                 std::string &decryptedText) {
  if (blockSize < 1 || keyV == nullptr || iv == nullptr) {
    return false;
  }
  int i, j, k, nRounds = unknownStringV.size(), nBytesStuffing;
  std::vector<unsigned char> knownStringV, plaintextFullVector, encryptedTextV;
  std::vector<unsigned char> unknownStringAuxV;
  std::string encryptedText;

  bool flag;
  for (i = 0; i < nRounds; ++i) {
    knownStringV.clear();
    if ((int)decryptedText.size() >= blockSize - 1) {
      for (j = 0; j < blockSize - 1; ++j) {
        knownStringV.push_back(
            decryptedText[decryptedText.size() - blockSize + 1 + j]);
      }
    } else {
      nBytesStuffing = blockSize - 1 - decryptedText.size();
      for (j = 0; j < nBytesStuffing; ++j) {
        knownStringV.push_back('A');
      }
      for (k = 0; j < blockSize - 1; ++j, ++k) {
        knownStringV.push_back(decryptedText[k]);
      }
    }
    if (debugFlagExtreme == true) {
      std::cout << "knownStringV round " << nRounds << ": ";
      for (k = 0; k < (int)knownStringV.size(); ++k) {
        printf("%.2x ", knownStringV[k]);
      }
      printf("\n");
    }
    /* update plaintextFullVector and cypherText */
    plaintextFullVector.clear();
    for (j = 0; j < (int)knownStringV.size(); ++j) {
      plaintextFullVector.push_back(knownStringV[j]);
    }
    for (j = 0; j < (int)unknownStringV.size(); ++j) {
      plaintextFullVector.push_back(unknownStringV[j]);
    }
    if (debugFlag == true) {
      printf("\nFull plaintext round %d: '", i + 1);
      for (j = 0; j < (int)plaintextFullVector.size(); ++j) {
        printf("%.2x ", plaintextFullVector[j]);
        if (j == (int)knownStringV.size() - 1) {
          printf("|| ");
        }
      }
      printf("'\n");
    }
    /* pad message */
    flag = padPKCS_7(plaintextFullVector, blockSize);
    if (flag == false) {
      perror("There was an error in the function 'padPKCS_7'.");
      exit(1);
    }
    encryptedText =
        aesEcbEncryption(plaintextFullVector, blockSize, keyV, iv, &flag);
    if (flag == false) {
      perror("There was a problem in the function 'aesEcbEncryption'.");
      exit(1);
    } else {
      convertStringToVectorBytes(encryptedText, encryptedTextV);
      if (debugFlag == true) {
        printf("\nFull cypherText round %d: '", i + 1);
        for (j = 0; j < (int)encryptedTextV.size(); ++j) {
          printf("%.2x ", encryptedTextV[j]);
          if (j == (int)knownStringV.size() - 1) {
            printf("|| ");
          }
        }
        printf("'\n");
      }
    }
    /* decrypt byte, one at a time */
    flag = decryptTextRound(knownStringV, encryptedTextV, blockSize, keyV, iv,
                            decryptedText);
    if (flag == false) {
      perror("There was a problem in the function 'decryptText'.");
      exit(1);
    }
    if (debugFlag == true) {
      printf("\nDecrypted text string round %d: '", i + 1);
      for (j = 0; j < (int)decryptedText.size(); ++j) {
        printf("%.2x ", decryptedText[j]);
      }
      printf("'\n\n\n");
    }
    /* update unknownStringV */
    unknownStringAuxV.clear();
    copy(unknownStringV.begin() + 1, unknownStringV.end(),
         back_inserter(unknownStringAuxV));
    unknownStringV.clear();
    copy(unknownStringAuxV.begin(), unknownStringAuxV.end(),
         back_inserter(unknownStringV));
  }
  return true;
}
/******************************************************************************/
/* this function makes the decryption of the encryptedTextV content, the last
byte of the block, in the end it updates the decryptedText string and
returns true if all ok or false otherwise */
bool decryptTextRound(const std::vector<unsigned char> &knownStringV,
                      const std::vector<unsigned char> &encryptedTextV,
                      const int blockSize, unsigned char *keyV,
                      unsigned char *iv, std::string &decryptedText) {
  if (blockSize < 1 || keyV == nullptr || iv == nullptr) {
    return false;
  }
  int i;
  std::vector<unsigned char> previousVectorKnow;
  std::map<std::string, unsigned char> dictionary;
  std::string keyD;
  bool flag;
  for (i = 0; i < (int)knownStringV.size(); ++i) {
    previousVectorKnow.push_back(knownStringV[i]);
  }
  /* dictionary calculation */
  flag =
      populateDictionary(dictionary, previousVectorKnow, blockSize, keyV, iv);
  if (flag == false) {
    perror("There was a problem in the function 'populateDictionary'.");
    return false;
  }
  /* key calculation */
  keyD.clear();
  for (i = 0; i < blockSize; ++i) {
    keyD += encryptedTextV[i];
  }
  decryptedText += dictionary[keyD];
  previousVectorKnow.push_back(dictionary[keyD]);
  return true;
}
/*******************************************************************************/
/* this function makes the test if v1 and  v2 are equal considering the search
size as sizeSearch, it returns true the vectors are equal, false otherwise, it
will also set the flagWithoutError to true if no errors, false otherwise */
bool testEqualVectors(std::vector<unsigned char> &v1,
                      std::vector<unsigned char> &v2,
                      const unsigned int sizeSearch, bool &flagWithoutError) {
  if (v1.size() < sizeSearch || v2.size() < sizeSearch) {
    flagWithoutError = false;
    return false;
  } else {
    flagWithoutError = true;
  }
  int i;
  for (i = 0; i < (int)sizeSearch; ++i) {
    if (v1[i] != v2[i]) {
      return false;
    }
  }
  return true;
}
/******************************************************************************/
/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s,
                                std::vector<unsigned char> &v) {
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
void convertVectorBytesToString(const std::vector<unsigned char> &v,
                                std::string &s) {
  int i, size = v.size();
  s.clear();
  for (i = 0; i < size; ++i) {
    s += v[i];
  }
  return;
}
/******************************************************************************/
/* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1,
                 const std::vector<unsigned char> &vS2,
                 std::vector<unsigned char> &vRes) {
  if (vS1.size() != vS2.size()) {
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
void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}
/******************************************************************************/
int aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen,
                        unsigned char *key, unsigned char *iv,
                        unsigned char *cyphertext) {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int cyphertextLen = 0;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
    handleErrors();
  }
  // EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
    handleErrors();
  }
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
    handleErrors();
  }
  cyphertextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return cyphertextLen;
}
/******************************************************************************/
/* this function makes the padding using PKCS#7 format, in the end it will
return the padding result by reference in the v vector and by value true if all
ok or false otherwise */
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize) {
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
/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string
aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
                 unsigned int blockSize, unsigned char *key, unsigned char *iv,
                 bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0 ||
      plainTextBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextVector, cypherTextVector;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  int nCycles, size, i, j, encryptedTextLen;
  /* work to be done */
  plainTextPointer =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (plainTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'plainTextPointer'.");
    *b = false;
    return encryptedText;
  }
  encryptedTextPointer =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (encryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'encryptedTextPointer'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullText.size();
  nCycles = size / blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill plainTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextVector.push_back(plainTextBytesAsciiFullText[blockSize * i + j]);
    }
    /* copy content of plainTextVector into plainTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextPointer[j] = plainTextVector[j];
    }
    memset(encryptedTextPointer, 0, 2 * blockSize + 1);
    /* Decrypt the ciphertext */
    encryptedTextLen = aesEcbEncryptWorker(plainTextPointer, blockSize, key, iv,
                                           encryptedTextPointer);
    if (debugFlagExtreme == true) {
      std::cout << "Full Decrypted ECB text size = " << encryptedTextLen
                << std::endl;
      BIO_dump_fp(stdout, (const char *)encryptedTextPointer, encryptedTextLen);
    }
    /* Add a NULL terminator. We are expecting printable text */
    encryptedTextPointer[encryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = fillVectorFromPointerArray(cypherTextVector, encryptedTextPointer,
                                      encryptedTextLen);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return encryptedText;
    }
    /* add cyphertext encrypted to the result */
    for (j = 0; j < encryptedTextLen; ++j) {
      encryptedText.push_back(cypherTextVector[j]);
    }
  }
  /* free memory */
  free(plainTextPointer);
  free(encryptedTextPointer);
  if (debugFlagExtreme == true) {
    std::cout << "Full Encrypted text size = " << encryptedText.size()
              << std::endl;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function makes the copy of blockSize bytes from the
previousCypherTextPointer into the vector previousCypherText, if all went ok it
will return true, false otherwise */
bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
                                const unsigned char *previousCypherTextPointer,
                                const unsigned int blockSize) {
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
/* this function makes the encryption of the plaintext, returning a oracleID
struture filled by value, and true by reference if all went ok or false
otherwise */
oracleID encryptionOracle(std::string plaintext, const int blockSize, bool *b) {
  oracleID id;
  std::string prefix, sufix, completePlainText, cypherText;
  std::vector<unsigned char> completePlainTextV;
  unsigned char *key =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  unsigned char *iv =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive.
  int i;
  bool b1;
  /* test memory allocations */
  if (key == nullptr || iv == nullptr || (int)appendBytesNumber > blockSize) {
    perror("There was an error in the memory allocation in the function "
           "'encryptionOracle'.");
    *b = false;
    return id;
  }
  /* fill prefix and sufix */
  for (i = 0; i < (int)appendBytesNumber; ++i) {
    prefix.push_back(dist1(gen));
    sufix.push_back(dist1(gen));
  }
  for (i = appendBytesNumber; i < blockSize; ++i) {
    prefix.push_back(0);
    sufix.push_back(0);
  }
  /* completePlainText generation */
  completePlainText = prefix + plaintext + sufix;
  convertStringToVectorBytes(completePlainText, completePlainTextV);
  /* pad message */
  b1 = padPKCS_7(completePlainTextV, blockSize);
  if (b1 == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    *b = false;
    return id;
  }
  /* encrypted using ECB mode */
  id.encryptionMode = "ECB";
  cypherText = aesEcbEncryption(completePlainTextV, blockSize, key, iv, &b1);
  convertStringToVectorBytes(cypherText, id.cyphertext);
  if (b1 == false) {
    perror("There was a problem in the function 'aesEcbEncryption'.");
    *b = true;
    return id;
  }
  /* free memory */
  memset(key, 0, 2 * blockSize + 1);
  memset(iv, 0, 2 * blockSize + 1);
  free(key);
  free(iv);
  /* return values */
  *b = true;
  return id;
}
/******************************************************************************/
/* this function makes the encryption of the plaintext, returning a oracleID
struture filled by value, and true by reference if all went ok or false
otherwise */
oracleID encryptionOracleWithoutPrefixAndSufix(std::string plaintext, bool *b) {
  oracleID id;
  std::string completePlainText, cypherText;
  std::vector<unsigned char> completePlainTextV;
  unsigned char *key =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  unsigned char *iv =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive.
  bool b1;
  /* test memory allocations */
  if (key == nullptr || iv == nullptr || (int)appendBytesNumber > blockSize) {
    perror("There was an error in the memory allocation in the function "
           "'encryptionOracle'.");
    *b = false;
    return id;
  }
  /* completePlainText generation */
  completePlainText = plaintext;
  convertStringToVectorBytes(completePlainText, completePlainTextV);
  /* pad message */
  b1 = padPKCS_7(completePlainTextV, blockSize);
  if (b1 == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    *b = false;
    return id;
  }
  /* encrypted using ECB mode */
  id.encryptionMode = "ECB";
  cypherText = aesEcbEncryption(completePlainTextV, blockSize, key, iv, &b1);
  convertStringToVectorBytes(cypherText, id.cyphertext);
  if (b1 == false) {
    perror("There was a problem in the function 'aesEcbEncryption'.");
    *b = true;
    return id;
  }
  /* free memory */
  memset(key, 0, 2 * blockSize + 1);
  memset(iv, 0, 2 * blockSize + 1);
  free(key);
  free(iv);
  /* return values */
  *b = true;
  return id;
}
/******************************************************************************/
/* this function makes the guess of the aes mode encryption, between ECB or CBC,
in the end it returns his guess by value and true by reference if no error was
detected or false otherwise */
std::string detector(const std::vector<unsigned char> &cypherText,
                     const int blockSize, bool *b) {
  std::string veredict = "?";
  if (cypherText.size() % blockSize != 0) {
    *b = false;
    return veredict;
  }
  if (cypherText.size() / blockSize < 4) {
    *b = true;
    return veredict;
  }
  int i;
  for (i = 0; i < blockSize; ++i) {
    if (cypherText[blockSize + i] != cypherText[2 * blockSize + i]) {
      veredict = "CBC";
      *b = true;
      return veredict;
    }
  }
  /* if it reaches here then c[1] = c[2] -> ECB mode */
  veredict = "ECB";
  *b = true;
  return veredict;
}
/******************************************************************************/
/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV,
                        std::map<unsigned char, int> &base64IndexMap,
                        std::vector<unsigned char> &encryptedBytesAscii) {
  if (sV.size() % 4 != 0) {
    return false;
  }
  int sizeString = sV.size(), i, j, k, validInputLetters = 0;
  int validOutputLetters = 0;
  unsigned char c, mapBase64Index[4] = {0};
  encryptedBytesAscii.clear();
  /* convert from base64 into bytes taking as input 4 base64 chars at each step
   */
  for (i = 0; i < sizeString; i += 4) {
    /* valid letters count, meaning different from '=' base64char */
    for (j = i, validInputLetters = 0; j < i + 4; ++j) {
      if (sV[j] != '=') {
        ++validInputLetters;
      }
    }
    /* convertion from base64 char into index of the base64 alphabet */
    for (j = i, k = 0; j < i + validInputLetters; ++j, ++k) {
      if (debugFlagExtreme == true) {
        printf("\nChar searching in map: %c -> %d", sV[j],
               base64IndexMap[(unsigned char)sV[j]]);
      }
      mapBase64Index[k] = base64IndexMap[(unsigned char)sV[j]];
    }
    if (debugFlagExtreme == true) {
      std::cout << "\nValidInputLetters for : '" << sV[i] << sV[i + 1]
                << sV[i + 2] << sV[i + 3] << "' is " << validInputLetters;
      std::cout << " with mapBase64Index: ";
      for (j = 0; j < 4; ++j) {
        printf("%d ", mapBase64Index[j]);
      }
      std::cout << std::endl;
    }
    /* valid input letters converted to valid output letters */
    validOutputLetters = validInputLetters - 1;
    for (j = 0; j < validOutputLetters; ++j) {
      if (j == 0) {
        /* 765432 | 10 */
        c = ((mapBase64Index[0] & 0x3F) << 2) |
            ((mapBase64Index[1] & 0x3F) >> 4);
      } else if (j == 1) {
        /* 7654 | 3210 */
        c = ((mapBase64Index[1] & 0x3F) << 4) |
            ((mapBase64Index[2] & 0x3F) >> 2);
      } else if (j == 2) {
        /* 76 | 543210 */
        c = ((mapBase64Index[2] & 0x3F) << 6) |
            ((mapBase64Index[3] & 0x3F) >> 0);
      }
      encryptedBytesAscii.emplace_back(c);
    }
  }
  return true;
}
/******************************************************************************/
