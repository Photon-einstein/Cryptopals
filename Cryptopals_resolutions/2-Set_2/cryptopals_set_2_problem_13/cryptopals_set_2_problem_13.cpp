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
#include <random>
#include <map>
#include <algorithm> // for copy() and assign()
#include <iterator> // for back_inserter

// To compile: $ g++ -Wall -std=c++17 cryptopals_set_2_problem_13.cpp -o cryptopals_set_2_problem_13 -lcrypto

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const bool debugFlag = true, debugFlagExtreme = false;
unsigned char *keyV;
unsigned char *iv;

typedef struct {
  std::string property;
  std::string value;
} jsonData;

/* this function makes the conversion of the string s into json format, updating
the map m, in the end it will return true if all went ok or false otherwise */
bool parseRoutineToJsonFormat(const std::string &s, std::vector<jsonData> &v);

/* this function makes the print of the json struture in the map m, in the end
returns true if all ok or false otherwise */
bool printJsonFormat(const std::string &structuredCookie, std::vector<jsonData> &v);

/* this function makes the encoding of a user email, this encoder does not allow
the characters '&' and '=' in that email so it will escape that characters,
it will return the encoded string by reference and if all went ok it will return
true if all ok or false otherwise */
bool profileFor(const std::string &email, std::string &encodedStringOutput);

/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize, std::string &key);

/* this function makes the padding using PKCS#7 format, in the end it will return
the padding result by reference in the v vector and by value true if all ok or
false otherwise */
bool padPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

/* this function makes the unpadding using PKCS#7 format, in the end it will return
the unpadding result by reference in the v vector and by value true if all ok or
false otherwise */
bool unpadPKCS_7(std::vector<unsigned char> &v, const unsigned int blockSize);

int aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen, const
  unsigned char *key, const unsigned char *iv, unsigned char *cyphertext);

int aesEcbDecryptWorker(unsigned char *cyphertext, int cypherTextLen,
  unsigned char *key, unsigned char *iv, unsigned char *plaintext);

void handleErrors(void);

/* this function does the encryption of aes-ecb mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

/* this function does the decryption of aes-ecb mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesEcbDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b);

/* this function makes the copy of blockSize bytes from the previousCypherTextPointer
into the vector previousCypherText, if all went ok it will return true, false
otherwise */
bool fillVectorFromPointerArray(std::vector<unsigned char> &previousCypherText,
  const unsigned char *previousCypherTextPointer, const unsigned int blockSize);

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v);

/* this function makes the fulling of the string s based on the content of the
vector v */
void convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s);

/* this function makes the sanitization of the email and after that it will
encrypt each block using aes ecb mode, returning the resulting cypherText in the
string encodedStringOutputEncrypted by reference, and it will also return by
true if all ok or false otherwise */
bool profileForOracleEncrypt(const std::string &email, std::string &encodedStringOutputEncrypted);

/* this function makes an attack into aes ecb mode, trying to forge an admin user
role to the email of the attacker, in the end it will return the encodedUserProfile
by reference and true if all went ok, false if there was an error */
bool ecbAttack(std::string &encodedUserProfile);

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string structuredCookie = "foo=bar&baz=qux&zap=zazzle";
  std::vector<jsonData> v;
  std::vector<unsigned char> plainTextBytesAsciiFullText, encryptedBytesAsciiFullText;
  bool b;
  std::string nastyEmail = "foo@bar.com&role=admin", encodedStringOutput="";
  std::string correctEmail = "foo@bar.com&role=user";
  std::string key, testEncryptionString, encodedUserProfileEncrypted;
  std::string encodedUserProfile;
  int i;
  /*step 1: test parse routine */
  b = parseRoutineToJsonFormat(structuredCookie, v);
  if (b == false) {
    perror("There was a problem in the function 'parseRoutineToJsonFormat'.");
    exit(1);
  }
  b = printJsonFormat(structuredCookie, v);
  if (b == false) {
    perror("There was a problem in the function 'printJsonFormat'.");
    exit(1);
  }
  /* step 2: encode a user profile */
  b = profileFor(nastyEmail, encodedStringOutput);
  if (b == false) {
    std::cout<<"There was a problem in the function 'profileEncoder'.";
    exit(1);
  }
  std::cout<<"\nEncoded email='"<<nastyEmail<<"' with role user as: '"<<encodedStringOutput<<"'."<<std::endl;
  /* step 3: key generation */
  b = keyFilling(blockSize, key);
  if (b == false) {
    perror("\nThere was an error in the function 'keyFilling'.");
    exit(1);
  }
  /* step 4: prepare keyV and iv for later on do the
  encrypt: plaintext || unknown-string with random key in the next step */
  keyV = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  if (keyV == nullptr || iv == nullptr) {
    perror("There was a problem in the memory allocation.");
    exit(1);
  }
  for (i = 0; i < (int)key.size(); ++i) {
    keyV[i] = key[i];
  }
  /* step 5.1: Encrypt the encoded user profile under the key -> 'aesEcbEncryption' */
  convertStringToVectorBytes(correctEmail, plainTextBytesAsciiFullText);
  /* pad message */
  b = padPKCS_7(plainTextBytesAsciiFullText, blockSize);
  if (b == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    exit(1);
  }
  testEncryptionString = aesEcbEncryption(plainTextBytesAsciiFullText,
    blockSize, keyV, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesEcbEncryption'.");
    exit(1);
  }
  /* step 5.2: Decrypt the encoded user profile and parse it -> 'aesEcbDecryption' */
  convertStringToVectorBytes(testEncryptionString, encryptedBytesAsciiFullText);
  testEncryptionString = aesEcbDecryption(encryptedBytesAsciiFullText,
    blockSize, keyV, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesEcbDecryption'.");
    exit(1);
  }
  /* step 5.3: Test the correct work of the function 'aesEcbEncryption' and
  * 'aesEcbDecryption' */
  if (correctEmail == testEncryptionString) {
    std::cout<<"\nThe functions 'aesEcbEncryption' and 'aesEcbDecryption' are working well, test passed, string tested: '"
    <<testEncryptionString<<"', size = "<<testEncryptionString.size()<<"."<<std::endl;
  } else {
    std::cout<<"\nThe functions 'aesEcbEncryption' and 'aesEcbDecryption' aren't working well, test failed."<<std::endl;
  }
  /* step 6: test the proper function of 'aesEcbEncryption' and 'aesEcbDecryption' */
  b = ecbAttack(encodedUserProfileEncrypted);
  if (b == false) {
    perror("There was an error in the function 'ecbAttack'.");
    exit(1);
  }
  /* step 7: decrypt the encodedUserProfile retrieved from the ecbAttack function */
  convertStringToVectorBytes(encodedUserProfileEncrypted, encryptedBytesAsciiFullText);
  encodedUserProfile = aesEcbDecryption(encryptedBytesAsciiFullText,
    blockSize, keyV, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesEcbDecryption'.");
    exit(1);
  }
  std::cout<<"\nThe encoded user profile retrieved from the function 'ecbAttack' was, cookie style: '"
    <<encodedUserProfile<<"'."<<std::endl;
  b = parseRoutineToJsonFormat(encodedUserProfile, v);
  if (b == false) {
    perror("There was a problem in the function 'parseRoutineToJsonFormat'.");
    exit(1);
  }
  b = printJsonFormat(encodedUserProfile, v);
  if (b == false) {
    perror("There was a problem in the function 'printJsonFormat'.");
    exit(1);
  }
  if (v.size() == 3 && v[2].property == "role" && v[2].value == "admin") {
    std::cout<<"\nTest passed."<<std::endl;
  } else {
    std::cout<<"\nTest failed."<<std::endl;
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
/* this function makes the conversion of the string s into json format, updating
the map m, in the end it will return true if all went ok or false otherwise */
bool parseRoutineToJsonFormat(const std::string &s, std::vector<jsonData> &v) {
  if (s.size() == 0) {
    return false;
  }
  v.clear();
  std::stringstream ss1(s);
  char del1 = '&', del2 = '=';
  std::string word, aux="";
  std::vector<std::string> param;
  int i;
  jsonData data;
  for(i = 0; i < 2; ++i) {
    param.push_back(aux);
  }
  while (ss1.eof() == false) {
     getline(ss1, word, del1);
     std::stringstream ss2(word);
     data.property.clear();
     data.value.clear();
     for(i = 0; i < 2; ++i) {
       param[i].clear();
       if(ss2.eof() == true) {
         return false;
       }
       getline(ss2, param[i], del2);
     }
    /* map update */
    if (param[0].size() == 0 || param[1].size() == 1) {
      return false;
    }
    data.property = param[0];
    data.value = param[1];
    v.push_back(data);
  }
  /* if it reaches here then all was ok */
  return true;
}
/******************************************************************************/
/* this function makes the print of the json struture in the map m, in the end
returns true if all ok or false otherwise */
bool printJsonFormat(const std::string &structuredCookie, std::vector<jsonData> &v) {
  if (v.size() == 0) {
    return false;
  }
  int i, size = v.size();
  std::cout<<"Structured cookie '"<<structuredCookie<<"' converted to json format as:"<<std::endl;
  for(i = 0; i < size; ++i) {
    if(v[i].property.size() == 0 || v[i].value.size() == 0) {
      return false;
    }
    if (i == 0) {
      std::cout<<"{"<<std::endl;
      std::cout<<"\t"<<v[i].property<<": '"<<v[i].value<<"'";
    } else {
      std::cout<<",\n\t"<<v[i].property<<": '"<<v[i].value<<"'";
    }
  }
  std::cout<<"\n}"<<std::endl;
  return true;
}
/******************************************************************************/
/* this function makes the encoding of a user email, this encoder does not allow
the characters '&' and '=' in that email so it will escape that characters,
it will return the encoded string by reference and if all went ok it will return
true if all ok or false otherwise */
bool profileFor(const std::string &email, std::string &encodedStringOutput) {
  if (email.size() == 0) {
    return false;
  }
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(10,99); // distribute results between 0 and 255 inclusive
  std::string emailAux, del="\\";
  int i, size = email.size();
  /* string sanitization, RFC 5322 to validate email, not done here */
  for(i = 0; i < size; ++i) {
    if (email[i] != '&' && email[i] != '=') {
      emailAux+=email[i];
    } else {
      emailAux+=del+email[i];
    }
  }
  if (emailAux.size() == 0) {
    return false;
  }
  /* encode string */
  encodedStringOutput.clear();
  encodedStringOutput = "email="+emailAux+"&uid="+std::to_string(dist(gen))+"&role="+"user";
  return true;
}
/******************************************************************************/
/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize, std::string &key) {
  if (blockSize < 1) {
    return false;
  }
  key.clear();
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,255); // distribute results between 0 and 25r inclusive
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
  if (debugFlag == true) {
    printf("\n\n");
  }
  return true;
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
int aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen, unsigned char *key,
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
int aesEcbDecryptWorker(unsigned char *cyphertext, int cypherTextLen, unsigned char *key,
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
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
/******************************************************************************/
/* this function does the encryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0 || plainTextBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextVector, cypherTextVector;
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
  size = plainTextBytesAsciiFullText.size();
  nCycles = size/blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill plainTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextVector.push_back(plainTextBytesAsciiFullText[blockSize*i+j]);
    }
    /* copy content of plainTextVector into plainTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextPointer[j] = plainTextVector[j];
    }
    memset(encryptedTextPointer, 0, 2*blockSize+1);
    /* Decrypt the cyphertext */
    encryptedTextLen = aesEcbEncryptWorker(plainTextPointer, blockSize,
    key, iv, encryptedTextPointer);
    if (debugFlagExtreme == true) {
      std::cout<<"Full Decrypted ECB text size = "<<encryptedTextLen<<std::endl;
      BIO_dump_fp (stdout, (const char *)encryptedTextPointer, encryptedTextLen);
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
  }
  /* free memory */
  free(plainTextPointer);
  free(encryptedTextPointer);
  if (debugFlagExtreme == true) {
    std::cout<<"Full Encrypted text size = "<<encryptedText.size()<<std::endl;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string aesEcbDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
  unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0 || encryptedBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
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
  size = encryptedBytesAsciiFullText.size();
  nCycles = size/blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      cypherTextPointer[j] = encryptedBytesAsciiFullText[blockSize*i+j];
    }
    /* Decrypt the ciphertext */
    decryptedTextLen = aesEcbDecryptWorker(cypherTextPointer, blockSize,
    key, iv, cypherTextDecryptedPointer);
    if (debugFlag == true) {
      std::cout<<"Iterative decrypted text size = "<<decryptedTextLen<<", block = "<<i+1<<"."<<std::endl;
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
    /* add cypherText to the result */
    for (j = 0; j < decryptedTextLen; ++j) {
      decryptedText.push_back(cypherText[j]);
    }
  }
  /* we need to unpad the decrypted text */
  convertStringToVectorBytes(decryptedText, decryptedTextVector);
  flag = unpadPKCS_7(decryptedTextVector, blockSize);
  if (flag == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    exit(1);
  }
  convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  free(cypherTextPointer);
  free(decryptedTextPointer);
  free(cypherTextDecryptedPointer);
  if (debugFlag == true) {
    std::cout<<"Full Decrypted text size after unpadding = "<<decryptedText.size()<<std::endl;
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
/* this function makes the sanitization of the email and after that it will
encrypt each block using aes ecb mode, returning the resulting cypherText in the
string encodedStringOutputEncrypted by reference, and it will also return by
true if all ok or false otherwise */
bool profileForOracleEncrypt(const std::string &email, std::string
      &encodedStringOutputEncrypted) {
  if (email.size() == 0) {
    return false;
  }
  encodedStringOutputEncrypted.clear();
  int i;
  bool b;
  std::string encodedStringOutput;
  std::vector<unsigned char> plainTextBytesAsciiFullText;
  b = profileFor(email, encodedStringOutput);
  if (b == false) {
    perror("There was a error in the function 'profileFor'.");
    return false;
  }
  if (debugFlag == true) {
    std::cout<<"'profileFor' output was: "<<std::endl;
    for (i = 0; i < (int)encodedStringOutput.size(); ++i) {
      if (isalpha(encodedStringOutput[i]) || encodedStringOutput[i] == '@' || encodedStringOutput[i] == '.'
      || encodedStringOutput[i] == '=' || encodedStringOutput[i] == '&') {
        printf("%c", encodedStringOutput[i]);
      } else {
        printf(" x%.2x", encodedStringOutput[i]);
      }
    }
    printf("\n\n");
  }
  convertStringToVectorBytes(encodedStringOutput, plainTextBytesAsciiFullText);
  /* pad message */
  b = padPKCS_7(plainTextBytesAsciiFullText, blockSize);
  if (b == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    return false;
  }
  encodedStringOutputEncrypted = aesEcbEncryption(plainTextBytesAsciiFullText,
    blockSize, keyV, iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesEcbEncryption'.");
    return true;
  }
  /* if it reaches here then all was ok */
  return true;
}
/******************************************************************************/
/* this function makes an attack into aes ecb mode, trying to forge an admin user
role to the email of the attacker, in the end it will return the encodedUserProfile
by reference and true if all went ok, false if there was an error */
bool ecbAttack(std::string &encodedUserProfileEncrypted) {
  encodedUserProfileEncrypted.clear();
  int nOs = blockSize - strlen("email=f") - strlen("@bar.");
  std::string attackMail = "f", adminSecondBlock = "admin";
  std::string encodedStringOutputEncrypted, encodedStringOutputAttack;
  int i, j, nBlocks = 3;
  std::vector<unsigned char> attackMailEncrypted(nBlocks*blockSize, 0);
  std::vector<unsigned char> adminSecondBlockV;
  bool b;
  if (debugFlag == true) {
    std::cout<<"Number of 'o' in the email will be equal to "<<nOs<<std::endl;
  }
  for (i = 0; i < nOs; ++i) {
    attackMail+="o";
  }
  attackMail+="@bar.";
  convertStringToVectorBytes(adminSecondBlock, adminSecondBlockV);
  b = padPKCS_7(adminSecondBlockV, blockSize);
  if (b == false) {
    perror("There was an error in the function 'padPKCS_7'");
    return false;
  }
  convertVectorBytesToString(adminSecondBlockV, adminSecondBlock);
  attackMail+=adminSecondBlock+"com";
  if (debugFlag == true) {
    std::cout<<"Attack mail is: "<<std::endl;
    for (i = 0; i < (int)attackMail.size(); ++i) {
      if (isalpha(attackMail[i]) || attackMail[i] == '@' || attackMail[i] == '.') {
        printf("%c", attackMail[i]);
      } else {
        printf(" x%.2x", attackMail[i]);
      }
    }
    printf("\n\n");
  }
  b = profileForOracleEncrypt(attackMail, encodedStringOutputEncrypted);
  if (b == false) {
    perror("There was a problem in the function 'profileForOracleEncrypt'.");
    return false;
  }
  for (i = 0; i < nBlocks; ++i) {
    for (j = 0; j < (int)blockSize; ++j) {
      if (i == 0) {
        attackMailEncrypted[j]=encodedStringOutputEncrypted[j];
      } else if (i == 1) {
        attackMailEncrypted[(i+1)*blockSize+j] = encodedStringOutputEncrypted[i*blockSize+j];
      } else {
        attackMailEncrypted[(i-1)*blockSize+j] = encodedStringOutputEncrypted[i*blockSize+j];
      }
    }
  }
  convertVectorBytesToString(attackMailEncrypted, encodedUserProfileEncrypted);
  return true;
}
/******************************************************************************/
