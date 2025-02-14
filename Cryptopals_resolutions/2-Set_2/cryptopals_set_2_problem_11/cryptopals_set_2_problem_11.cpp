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
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

// To compile: $ g++ -Wall -std=c++11 cryptopals_set_2_problem_11.cpp -o
// cryptopals_set_2_problem_11 -lcrypto

typedef struct {
  std::vector<unsigned char> cyphertext;
  std::string encryptionMode; /* 'ECB' or 'CBC' */
} oracleID;

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const unsigned int appendBytesNumber =
    5; /* number of bytes to add at the beggining and at the end, 'x|Message|x'
        */
const bool debugFlag = false;
const int nTests = 100;

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

/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string
aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
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

/* this function makes the guess of the aes mode encryption, between ECB or CBC,
in the end it returns his guess by value and true by reference if no error was
detected or false otherwise */
std::string detector(const std::vector<unsigned char> &cypherText,
                     const int blockSize, bool *b);

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string plaintext = "", detectorVeredict, veredict;
  oracleID id;
  int i;
  bool b;
  /* rest of the work */
  for (i = 0; i < (int)blockSize * 2; ++i) {
    plaintext.push_back(0);
  }
  /* run tests */
  for (i = 0; i < nTests; ++i) {
    id = encryptionOracle(plaintext, blockSize, &b);
    if (b == false) {
      perror("There was a problem in the function 'encryptionOracle'.");
      exit(1);
    }
    detectorVeredict = detector(id.cyphertext, blockSize, &b);
    if (b == false) {
      perror("There was a problem in the function 'detector'.");
      exit(1);
    }
    if (detectorVeredict == id.encryptionMode) {
      veredict = "Test passed";
    } else {
      veredict = "Test failed";
    }
    std::cout << "Test nº" << i + 1 << "\tOracle mode: " << id.encryptionMode
              << "\tDetector mode: " << detectorVeredict << "\t" << veredict
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
    if (debugFlag == true) {
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
  if (debugFlag == true) {
    std::cout << "Full Eecrypted text size = " << encryptedText.size()
              << std::endl;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string
aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
                 unsigned int blockSize, unsigned char *key, unsigned char *iv,
                 bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0 ||
      plainTextBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> previousCypherTextVector, plainTextVector, xorRes,
      cypherTextVector;
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
  flag = fillVectorFromPointerArray(previousCypherTextVector, iv, blockSize);
  if (flag == false) {
    perror(
        "\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullText.size();
  nCycles = size / blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextVector.push_back(plainTextBytesAsciiFullText[blockSize * i + j]);
    }
    /* previous cyphertext XOR plainText */
    flag = xorFunction(previousCypherTextVector, plainTextVector, xorRes);
    if (flag == false) {
      perror("\nThere was an error in the function 'xorFunction'.");
      *b = false;
      return encryptedText;
    }
    /* copy content of xorRes into cypherTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextPointer[j] = xorRes[j];
    }
    xorRes.clear();
    memset(encryptedTextPointer, 0, 2 * blockSize + 1);
    /* Decrypt the ciphertext */
    encryptedTextLen = aesEcbEncryptWorker(plainTextPointer, blockSize, key, iv,
                                           encryptedTextPointer);
    if (debugFlag == true) {
      std::cout << "Full Decrypted CBC text size = " << encryptedTextLen
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
    /* previousCypherText = cypherText */
    flag = fillVectorFromPointerArray(previousCypherTextVector,
                                      encryptedTextPointer, blockSize);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return encryptedText;
    }
  }
  /* free memory */
  free(plainTextPointer);
  free(encryptedTextPointer);
  if (debugFlag == true) {
    std::cout << "Full Decrypted text size = " << encryptedText.size()
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
  std::uniform_int_distribution<> dist1(0, 255),
      dist2(0, 1); // distribute results between 0 and 255 inclusive.
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
  if (dist1(gen) % 2 == 0) {
    /* encrypted using ECB mode */
    id.encryptionMode = "ECB";
    cypherText = aesEcbEncryption(completePlainTextV, blockSize, key, iv, &b1);
    convertStringToVectorBytes(cypherText, id.cyphertext);
    if (b1 == false) {
      perror("There was a problem in the function 'aesEcbEncryption'.");
      *b = true;
      return id;
    }
  } else {
    /* encrypted using CBC mode */
    id.encryptionMode = "CBC";
    cypherText = aesCbcEncryption(completePlainTextV, blockSize, key, iv, &b1);
    convertStringToVectorBytes(cypherText, id.cyphertext);
    if (b1 == false) {
      perror("There was a problem in the function 'aesCbcEncryption'.");
      *b = true;
      return id;
    }
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
