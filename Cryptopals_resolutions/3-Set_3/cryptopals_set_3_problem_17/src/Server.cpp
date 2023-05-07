#include <stdexcept>

#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Function.h"
#include "./../include/Server.h"

/* constructor / destructor */
Server::Server(const std::string inputFilePath, const std::shared_ptr<Pad>& pad) {
  Server::setBlockSize(blockSize);
  Server::setPad(pad);
  Server::setKey(_blockSize);
  Server::setIV(_blockSize);
  Server::loadInputStrings(inputFilePath);
}
/******************************************************************************/
Server::~Server() {
  memset(_key, 0, 2*_blockSize+1);
  memset(_iv, 0, 2*_blockSize+1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* setters */
void Server::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void Server::setPad(const std::shared_ptr<Pad>& pad) {
  _pad = pad;
}
/******************************************************************************/
void Server::setKey(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _key = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  if (_key == nullptr) {
    throw std::invalid_argument("There was a problem in the memory allocation of _key.");
  };
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,255); // distribute results between 0 and 25r inclusive
  int i;
  if(debugFlag == true) {
    printf("\nKey generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    _key[i] = dist1(gen);
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)_key[i]);
    }
  }
  printf("\n");
  return;
}
/******************************************************************************/
void Server::setIV(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  if (_iv == nullptr) {
    throw std::invalid_argument("There was a problem in the memory allocation of _iv.");
  };
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,255); // distribute results between 0 and 255 inclusive
  int i;
  if(debugFlag == true) {
    printf("\nIV generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    _iv[i] = dist1(gen);
    _ivV.push_back(_iv[i]);
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)_iv[i]);
    }
  }
  printf("\n\n");
  return;
}
/******************************************************************************/
/* getters */
int Server::getBlockSize() {
  return _blockSize;
}
/******************************************************************************/
unsigned char* Server::getKey() {
  return _key;
}
/******************************************************************************/
unsigned char* Server::getIV() {
  return _iv;
}
/******************************************************************************/
/* this function does the encryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string Server::aesCbcEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
    unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string encryptedText="";
  if (b == nullptr) {
    return encryptedText;
  } else if (plainTextBytesAsciiFullText.size() == 0) {
    *b = true;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextBytesAsciiFullTextCopy, cypherTextVector;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  int size, i, encryptedTextLen, size2=plainTextBytesAsciiFullText.size();
  for (i = 0; i < plainTextBytesAsciiFullText.size(); ++i) {
    plainTextBytesAsciiFullTextCopy.push_back(plainTextBytesAsciiFullText[i]);
  }
  /* padd plaintext before encryption */
  flag = _pad->pad(plainTextBytesAsciiFullTextCopy);
  if (flag == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullTextCopy.size();
  /* work to be done */
  plainTextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (plainTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'plainTextPointer'.");
    *b = false;
    return encryptedText;
  }
  encryptedTextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (encryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'encryptedTextPointer'.");
    *b = false;
    return encryptedText;
  }
  /* copy content of plainTextVector into plainTextPointer */
  for (i = 0; i < size; ++i) {
    plainTextPointer[i] = plainTextBytesAsciiFullTextCopy[i];
  }
  encryptedTextLen = Server::aesCbcEncryptWorker(plainTextPointer, size2,
  _key, _iv, encryptedTextPointer);
  if (debugFlag == true) {
    std::cout<<"Full Encrypted ECB text size = "<<encryptedTextLen<<" bytes."<<std::endl;
    BIO_dump_fp (stdout, (const char *)encryptedTextPointer, encryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  encryptedTextPointer[encryptedTextLen] = '\0';
  /* fill cyphertext vector */
  flag = Function::fillVectorFromPointerArray(cypherTextVector, encryptedTextPointer, encryptedTextLen);
  if (flag == false) {
    perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  /* add cyphertext encrypted to the result */
  Function::convertVectorBytesToString(cypherTextVector, encryptedText);
  /* free memory */
  memset(plainTextPointer, 0, size+1);
  memset(encryptedTextPointer, 0, size+1);
  free(plainTextPointer);
  free(encryptedTextPointer);
  *b = true;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string Server::aesCbcDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0 || encryptedBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *cypherTextPointer, *cypherTextDecryptedPointer;
  bool flag;
  int nCycles, size, i, decryptedTextLen;
  /* work to be done */
  size = encryptedBytesAsciiFullText.size();
  cypherTextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (cypherTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  cypherTextDecryptedPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (cypherTextDecryptedPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  /* fill cyperTextPointer */
  for (i = 0; i < size; ++i) {
    cypherTextPointer[i] = encryptedBytesAsciiFullText[i];
  }
  /* Decrypt the ciphertext */
  decryptedTextLen = Server::aesCbcDecryptWorker(cypherTextPointer, size,
  key, iv, cypherTextDecryptedPointer);
  if (debugFlagExtreme == true) {
    std::cout<<"Full Decrypted text size = "<<decryptedTextLen<<" bytes."<<std::endl;
    BIO_dump_fp (stdout, (const char *)cypherTextDecryptedPointer, decryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  cypherTextDecryptedPointer[decryptedTextLen] = '\0';
  /* fill cyphertext vector */
  flag = Function::fillVectorFromPointerArray(decryptedTextVector, cypherTextDecryptedPointer, decryptedTextLen);
  if (flag == false) {
    perror("\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return decryptedText;
  }
  Function::convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  memset(cypherTextPointer, 0, size);
  memset(cypherTextDecryptedPointer, 0, size);
  free(cypherTextPointer);
  free(cypherTextDecryptedPointer);
  *b = true;
  return decryptedText;
}
/******************************************************************************/
void Server::handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
/******************************************************************************/
int Server::aesCbcEncryptWorker(unsigned char *plaintext, int plaintextLen, unsigned char *key,
            unsigned char *iv, unsigned char *cyphertext) {
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int cyphertextLen=0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        Server::handleErrors();
    }
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        Server::handleErrors();
    }
    //EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
        Server::handleErrors();
    }
    cyphertextLen = len;
    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
        Server::handleErrors();
    }
    cyphertextLen += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return cyphertextLen;
}
/******************************************************************************/
int Server::aesCbcDecryptWorker(unsigned char *cyphertext, int cypherTextLen, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintextLen;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        Server::handleErrors();
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        Server::handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
        Server::handleErrors();
    plaintextLen = len;
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        Server::handleErrors();
    plaintextLen += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintextLen;
}
/******************************************************************************/
/* this function loads the input string from the file 'inputFilePath' into the
vector strings, in the end it just returns */
void Server::loadInputStrings(const std::string inputFilePath) {
  if (inputFilePath.size() == 0) {
    throw std::invalid_argument("Bad 'inputFilePath' | file path cannot be empty");
  }
  std::ifstream inputFile;
  inputFile.open(inputFilePath, std::ios::in);
  std::string lineReadBase64, lineReadAscii;
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  std::vector<unsigned char> lineReadAsciiVector, lineReadBase64Vector;
  bool b;
  int i;
  /* test ifstream */
  if (!inputFile) {
    throw std::invalid_argument("Bad 'inputFilePath' | failed to open the file ");
  } else if (debugFlagExtreme == true) {
    std::cout<<"\nThe file 'serverInput.txt' was sucessfully opened.\n"<<std::endl;
  }
  /* base64IndexMap */
  for(i = 0; i < (int)base64CharsDecoder.size(); ++i) {
    base64IndexMap[base64CharsDecoder[i]] = i;
  }
  if (debugFlagExtreme == true) {
    std::cout<<"Base 64 dictionary mapping:"<<std::endl;
    for (it = base64IndexMap.begin(); it != base64IndexMap.end(); ++it) {
      std::cout<<it->first<<" - "<<it->second<<std::endl;
    }
    printf("\n");
  }
  while(inputFile.good() == true) {
    lineReadBase64.clear();
    lineReadBase64Vector.clear();
    lineReadAsciiVector.clear();
    std::getline(inputFile, lineReadBase64);
    if (lineReadBase64.size() > 0) {
      Function::convertStringToVectorBytes(lineReadBase64, lineReadBase64Vector);
      b = Function::decodeBase64ToByte(lineReadBase64Vector, base64IndexMap, lineReadAsciiVector);
      if (b == false) {
        throw std::invalid_argument("There was an error in the function 'decodeBase64ToByte'.");
      }
      Function::convertVectorBytesToString(lineReadAsciiVector, lineReadAscii);
      if (debugFlagExtreme == true) {
        std::cout<<"Line read (base64): '"<<lineReadBase64<<"'"<<std::endl;
      }
      if (debugFlag == true) {
        std::cout<<"Line read (ascii): '"<<lineReadAscii<<"'"<<std::endl;
      }
      /* store the data in the server */
      /* base64 format */
      _stringsBase64.emplace_back(lineReadBase64);
      _stringsSetBase64.insert(lineReadBase64);
      /* ascii format */
      _stringsAscii.emplace_back(lineReadAscii);
      _stringsSetAscii.insert(lineReadAscii);
    }
  }
  return;
}
/******************************************************************************/
/* this function should select a string from the set of strings stored at
the server, encrypt and then return by reference the ciphertext and the iv
used, it should also return also true if all went ok or false otherwise */
bool Server::encryptionSessionTokenAesCbcMode(std::vector<unsigned char> &ciphertextV,
  std::vector<unsigned char> &iv) {
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,_stringsAscii.size()-1); // distribute results between 0 and 255 inclusive
  std::vector<unsigned char> plainTextBytesAsciiFullText;
  std::string ciphertext;
  int i = dist1(gen), j;
  bool b;
  if (debugFlagExtreme == true) {
    std::cout<<"\nRandom string selected was: "<<i+1<<" | '"<<_stringsAscii[i]<<"' | size "<<_stringsAscii[i].size()<<" bytes.\n"<<std::endl;
  }
  Function::convertStringToVectorBytes(_stringsAscii[i], plainTextBytesAsciiFullText);
  ciphertext = Server::aesCbcEncryption(plainTextBytesAsciiFullText,
    _blockSize, _key, _iv, &b);
  if (b == false) {
    perror("There was an error in the function 'aesCbcEncryption'.");
    return false;
  }
  /* filling output arguments of the function */
  Function::convertStringToVectorBytes(ciphertext, ciphertextV);
  iv.clear();
  copy(_ivV.begin(), _ivV.end(), back_inserter(iv));
  return true;
}
/******************************************************************************/
/* this function should consume the ciphertext produced by the function
'encryptionSessionTokenAesCbcMode' decrypt it, check its padding, and return
true or false depending on whether the padding is valid or not by reference
in the returnValue, and should return true if all when ok or false otherwise */
bool Server::decryptAndCheckPaddingInSessionTokenAesCbcMode(const std::vector<unsigned char>
      ciphertextV, bool *returnValue) {
  if (ciphertextV.size() == 0 || returnValue == nullptr) {
    return false;
  }
  bool flag;
  std::string plaintext;
  std::vector<unsigned char> plaintextV;
  plaintext = Server::aesCbcDecryption(ciphertextV, _blockSize, _key, _iv, &flag);
  if (flag == false) {
    perror("There was an error in the function 'aesCbcDecryption'.");
    return false;
  }
  Function::convertStringToVectorBytes(plaintext, plaintextV);
  /* preparing return values of the function */
  *returnValue = _pad->testPadding(plaintextV);
  return true;
}
/******************************************************************************/
/* this function makes the test if a possibleSessionToken is in fact present
in the server, if yes then this function will return true, false otherwise */
bool Server::checkPresenceOfValidSessionToken(const std::string &possibleSessionToken) {
  return _stringsSetAscii.count(possibleSessionToken) > 0;
}
/******************************************************************************/
