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

// To compile: $ g++ -Wall -std=c++11 cryptopals_set_1_problem_7.cpp -o cryptopals_set_1_problem_7 -lcrypto

/* this field contains the alphabet of the base64 format */
const std::string base64CharsDecoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const bool debugFlag = false;


/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
  &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii);

  /* this function makes the conversion from a string into a vector of bytes,
  in the end it just returns*/
  void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

void handleErrors(void);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  unsigned char *key = (unsigned char *)"YELLOW SUBMARINE";
  unsigned char *iv = NULL;
  unsigned char *cypherText;
  unsigned char *decryptedText;
  int decryptedTextLen, cypherTextLen;
  // other variables
  std::ifstream inputFile;
  inputFile.open("cryptopals_set_1_problem_7_dataset.txt", std::ios::in);
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  std::vector<unsigned char> encryptedBytesAsciiFullText, encryptedBytesAscii;
  std::vector<unsigned char> lineReadBase64Vector;
  std::string lineReadBase64;
  int i, size;
  bool b;
  if (!inputFile) {
    perror("File failed to be opened.");
    exit(1);
  } else {
    std::cout<<"The file 'cryptopals_set_1_problem_7_dataset.txt' was sucessfully opened."<<std::endl;
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
  /* cyperText memory allocation */
  cypherTextLen = encryptedBytesAsciiFullText.size();
  cypherText = (unsigned char*) calloc(cypherTextLen+1, sizeof (unsigned char));
  if (cypherText == nullptr) {
    perror("There was a problem in the memory allocation of the 'cyperText' pointer.");
    exit(1);
  }
  /* copy of the cyperText */
  for(i = 0; i < encryptedBytesAsciiFullText.size(); ++i) {
    cypherText[i] = encryptedBytesAsciiFullText[i];
  }
  decryptedTextLen = encryptedBytesAsciiFullText.size();
  decryptedText = (unsigned char*) calloc(decryptedTextLen+1, sizeof (unsigned char));
  if (decryptedText == nullptr) {
    perror("There was a problem in the memory allocation of the 'decryptedText' pointer.");
    exit(1);
  }
  std::cout<<"Raw data in binary: "<<std::endl;
  BIO_dump_fp (stdout, (const char *)cypherText, cypherTextLen);
  std::cout<<std::endl;
  /* Decrypt the ciphertext */
  decryptedTextLen = decrypt(cypherText, cypherTextLen, key, iv, decryptedText);
  /* Add a NULL terminator. We are expecting printable text */
  decryptedText[decryptedTextLen] = '\0';
  /* Show the decrypted text */
  printf("\n\nDecrypted text is:\n\n'");
  printf("%s'\n", decryptedText);
  /* free memory */
  free(cypherText);
  free(decryptedText);
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
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
/******************************************************************************/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
/******************************************************************************/
