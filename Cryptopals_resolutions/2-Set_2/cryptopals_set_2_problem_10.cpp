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

// To compile: $ g++ -Wall -std=c++11 cryptopals_set_2_problem_10.cpp -o cryptopals_set_2_problem_10 -lcrypto

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const bool debugFlag = false;


/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
  &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2,
  std::vector<unsigned char> &vRes);

void handleErrors(void);

int encrypt(unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

/* this function makes the padding using PKCS#7 format, in the end it will return
the padding result by reference in the v vector and by value true if all ok or
false otherwise */
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

/* this function makes the unpadding using PKCS#7 format, in the end it will return
the unpadding result by reference in the v vector and by value true if all ok or
false otherwise */
bool unpadPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

/* this function does the encryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

/* this function does the decryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesCbcDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

/* this function makes the copy of blockSize bytes from the previousCypherTextPointer
into the vector previousCypherText, if all went ok it will return true, false
otherwise */
bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
  const unsigned char *previousCypherTextPointer, const unsigned int blockSize);

/* this function tests the encryption of a given string of test, performing the
encryption and decryption of the aes 128 bits in cbc mode, if the test passes
then it will return true, false otherwise */
bool testEncryptDecrypt();

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  unsigned char *key = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  memcpy(key, "YELLOW SUBMARINE", strlen("YELLOW SUBMARINE")+1);//(unsigned char *)"YELLOW SUBMARINE";
  unsigned char *iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  std::string decryptedText;
  // other variables
  std::ifstream inputFile;
  inputFile.open("cryptopals_set_2_problem_10_dataset.txt", std::ios::in);
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  std::vector<unsigned char> encryptedBytesAsciiFullText, encryptedBytesAscii;
  std::vector<unsigned char> lineReadBase64Vector, decryptedTextVector;
  std::string lineReadBase64;
  int i, size;
  bool b;
  if (!inputFile) {
    perror("File failed to be opened.");
    exit(1);
  } else {
    std::cout<<"The file 'cryptopals_set_2_problem_10_dataset.txt' was sucessfully opened."<<std::endl;
  }
  /* base64IndexMap */
  for(i = 0; i < (int)base64CharsDecoder.size(); ++i) {
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
    lineReadBase64Vector.clear();
    encryptedBytesAscii.clear();
    std::getline(inputFile, lineReadBase64);
    convertStringToVectorBytes(lineReadBase64, lineReadBase64Vector);
    if (debugFlag == true) {
      /* full text print just to check */
      std::cout<<"Input read line in base64 to convert (string):\n'"<<lineReadBase64<<"'"<<std::endl;
      std::cout<<"Input read line in base64 to convert: \n'";
      for (i = 0; i < (int)lineReadBase64Vector.size(); ++i) {
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
      for (i = 0; i < (int)encryptedBytesAscii.size(); ++i) {
        printf("%.2x ", encryptedBytesAscii[i]);
      }
      printf("'\n\n");
    }
    /* pass data read line by line into the full vector data */
    size = encryptedBytesAscii.size();
    for(i = 0; i < size; ++i) {
      encryptedBytesAsciiFullText.emplace_back(encryptedBytesAscii[i]);
    }
  }
  if (debugFlag == true) {
    std::cout<<"Full text read line in binary to decrypt:\n'";
    for (i = 0; i < (int)encryptedBytesAsciiFullText.size(); ++i) {
      printf("%.2x ", encryptedBytesAsciiFullText[i]);
    }
    printf("'\n\n");
    fflush(NULL);
  }
  /* AES-CBC mode decryption */
  decryptedText = aesCbcDecryption(encryptedBytesAsciiFullText, blockSize, key, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesCbcDecryption'.");
    exit(1);
  }
  /* we need to unpad the decrypted text */
  convertStringToVectorBytes(decryptedText, decryptedTextVector);
  b = unpadPKCS_7(decryptedTextVector, blockSize);
  if (b == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    exit(1);
  }
  convertVectorBytesToString(decryptedTextVector, decryptedText);
  std::cout<<"\nDecrypted Text:\n'"<<decryptedText<<"'"<<std::endl;
  b = testEncryptDecrypt();
  if (b == true) {
    std::cout<<"\nEncrypt-decrypt test passed :)"<<std::endl;
  } else {
    std::cout<<"\nEncrypt-decrypt test failed :("<<std::endl;
  }
  /* free memory */
  free(key);
  free(iv);
  /* close file */
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
  v.clear();
  for (i = 0; i < size; ++i) {
    v.emplace_back(s[i]);
  }
  return;
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
/* this function makes the xor calculation of: sRes = vS1 xor vS2, if there is a
error it returns false */
bool xorFunction(const std::vector<unsigned char> &vS1, const std::vector<unsigned char> &vS2,
    std::vector<unsigned char> &vRes) {
  if (vS1.size() != vS2.size()) {
    return false;
  }
  int i, size = vS1.size();
  vRes.clear();
  for (i = 0; i < size; ++i) {
    vRes.push_back(vS1[i]^vS2[i]);
  }
  return true;
}
/******************************************************************************/
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
/******************************************************************************/
int encrypt(unsigned char *plaintext, int plaintextLen, unsigned char *key,
            unsigned char *iv, unsigned char *cyphertext) {
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int cyphertextLen=0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
        handleErrors();
    }
    //EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
        handleErrors();
    }
    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
        handleErrors();
    }
    cyphertextLen += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return cyphertextLen;
}
/******************************************************************************/
int decrypt(unsigned char *cyphertext, int cypherTextLen, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintextLen;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
        handleErrors();
    plaintextLen = len;
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintextLen += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintextLen;
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
/* this function does the encryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0 || plainTextBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> previousCypherTextVector, plainTextVector, xorRes, cypherTextVector;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  int nCycles, size, i, j, encryptedTextLen;
  /* work to be done */
  plainTextPointer = (unsigned char*) calloc(2*blockSize+1, sizeof (unsigned char));
  if (plainTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'plainTextPointer'.");
    *b = false;
    return encryptedText;
  }
  encryptedTextPointer = (unsigned char*) calloc(2*blockSize+1, sizeof (unsigned char));
  if (encryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'encryptedTextPointer'.");
    *b = false;
    return encryptedText;
  }
  flag = fillVectorFromPointerArray(previousCypherTextVector, iv, blockSize);
  if (flag == false) {
    perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullText.size();
  nCycles = size/blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextVector.push_back(plainTextBytesAsciiFullText[blockSize*i+j]);
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
    memset(encryptedTextPointer, 0, 2*blockSize+1);
    /* Decrypt the ciphertext */
    encryptedTextLen = encrypt(plainTextPointer, blockSize,
    key, iv, encryptedTextPointer);
    if (debugFlag == true) {
      std::cout<<"Full Decrypted text size = "<<encryptedTextLen<<std::endl;
    }
    /* Add a NULL terminator. We are expecting printable text */
    encryptedTextPointer[encryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = fillVectorFromPointerArray(cypherTextVector, encryptedTextPointer, encryptedTextLen);
    if (flag == false) {
      perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return encryptedText;
    }
    /* add cyphertext encrypted to the result */
    for (j = 0; j < encryptedTextLen; ++j) {
      encryptedText.push_back(cypherTextVector[j]);
    }
    /* previousCypherText = cypherText */
    flag = fillVectorFromPointerArray(previousCypherTextVector, encryptedTextPointer, blockSize);
    if (flag == false) {
      perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return encryptedText;
    }
  }
  /* free memory */
  free(plainTextPointer);
  free(encryptedTextPointer);
  if (debugFlag == true) {
    std::cout<<"Full Decrypted text size = "<<encryptedText.size()<<std::endl;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesCbcDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0 || encryptedBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> previousCypherText, cypherText, xorRes;
  unsigned char *cypherTextPointer, *decryptedTextPointer, *cypherTextDecryptedPointer;
  bool flag;
  int nCycles, size, i, j, decryptedTextLen;
  /* work to be done */
  cypherTextPointer = (unsigned char*) calloc(2*blockSize+1, sizeof (unsigned char));
  if (cypherTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  decryptedTextPointer = (unsigned char*) calloc(2*blockSize+1, sizeof (unsigned char));
  if (decryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'decryptedTextPointer'.");
    *b = false;
    return decryptedText;
  }
  cypherTextDecryptedPointer = (unsigned char*) calloc(2*blockSize+1, sizeof (unsigned char));
  if (cypherTextDecryptedPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  flag = fillVectorFromPointerArray(previousCypherText, iv, blockSize);
  if (flag == false) {
    perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return decryptedText;
  }
  size = encryptedBytesAsciiFullText.size();
  nCycles = size/blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      cypherTextPointer[j] = encryptedBytesAsciiFullText[blockSize*i+j];
    }
    /* Decrypt the ciphertext */
    decryptedTextLen = decrypt(cypherTextPointer, blockSize,
    key, iv, cypherTextDecryptedPointer);
    if (debugFlag == true) {
      std::cout<<"Full Decrypted text size = "<<decryptedTextLen<<std::endl;
    }
    /* Add a NULL terminator. We are expecting printable text */
    cypherTextDecryptedPointer[decryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = fillVectorFromPointerArray(cypherText, cypherTextDecryptedPointer, decryptedTextLen);
    if (flag == false) {
      perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return decryptedText;
    }
    /* previous cyphertext XOR Decrypted CypherText */
    flag = xorFunction(previousCypherText, cypherText, xorRes);
    if (flag == false) {
      perror("\nThere was an error in the function 'xorFunction'.");
      *b = false;
      return decryptedText;
    }
    /* add vRes to the result */
    for (j = 0; j < decryptedTextLen; ++j) {
      decryptedText.push_back(xorRes[j]);
    }
    /* previousCypherText = cypherText */
    flag = fillVectorFromPointerArray(previousCypherText, cypherTextPointer, blockSize);
    if (flag == false) {
      perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return decryptedText;
    }
  }
  /* free memory */
  free(cypherTextPointer);
  free(decryptedTextPointer);
  free(cypherTextDecryptedPointer);
  if (debugFlag == true) {
    std::cout<<"Full Decrypted text size = "<<decryptedText.size()<<std::endl;
  }
  return decryptedText;
}
/******************************************************************************/
/* this function makes the copy of blockSize bytes from the previousCypherTextPointer
into the vector previousCypherText, if all went ok it will return true, false
otherwise */
bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
  const unsigned char *previousCypherTextPointer, const unsigned int blockSize) {
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
/* this function tests the encryption of a given string of test, performing the
encryption and decryption of the aes 128 bits in cbc mode, if the test passes
then it will return true, false otherwise */
bool testEncryptDecrypt() {
  unsigned char *key = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  memcpy(key, "YELLOW SUBMARINE", strlen("YELLOW SUBMARINE")+1);//(unsigned char *)"YELLOW SUBMARINE";
  unsigned char *iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  bool b;
  std::vector<unsigned char> plaintextVector, cypherTextVector, decryptedTextVector;
  std::string stringTest = "Ehrsam, Meyer, Smith and Tuchman invented the cipher\n";
  stringTest+="block chaining (CBC) mode of operation in 1976.[23] In CBC mode, each block\n";
  stringTest+="of plaintext is XORed with the previous ciphertext block before being encrypted.\n";
  stringTest+="This way, each ciphertext block depends on all plaintext blocks processed up to\n";
  stringTest+="that point. To make each message unique, an initialization vector must be used\n";
  stringTest+="in the first block.";
  std::string cypherText, decryptedText;
  convertStringToVectorBytes(stringTest, plaintextVector);
  b = padPKCS_7(plaintextVector, blockSize);
  if (b == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    exit(1);
  }
  /* AES-CBC mode decryption */
  cypherText = aesCbcEncryption(plaintextVector, blockSize, key, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesCbcEncryption'.");
    exit(1);
  }
  convertStringToVectorBytes(cypherText, cypherTextVector);
  /* AES-CBC mode decryption */
  decryptedText = aesCbcDecryption(cypherTextVector, blockSize, key, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesCbcDecryption'.");
    exit(1);
  }
  /* we need to unpad the decrypted text */
  convertStringToVectorBytes(decryptedText, decryptedTextVector);
  b = unpadPKCS_7(decryptedTextVector, blockSize);
  if (b == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    exit(1);
  }
  convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  free(iv);
  free(key);
  std::cout<<"\nDecrypted Text use in Encrypt/Decrypt test:\n\n'"<<decryptedText<<"'"<<std::endl;
  if (stringTest == decryptedText) {
    return true;
  } else {
    return false;
  }
}
/******************************************************************************/
