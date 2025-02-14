#include <stdexcept>

#include "./../include/Function.h"
#include "./../include/Server.h"

/* constructor / destructor */
Server::Server(const std::string inputFilePath) {
  Server::setBlockSize(blockSize);
  Server::setKey(_blockSize);
  Server::setIV(_blockSize);
  Server::loadInputStrings(inputFilePath);
}
/******************************************************************************/
Server::~Server() {
  memset(_key, 0, 2 * _blockSize + 1);
  memset(_iv, 0, 2 * _blockSize + 1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* setters */
void Server::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void Server::setKey(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  int i;
  _key = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (_key == nullptr) {
    throw std::invalid_argument(
        "There was a problem in the memory allocation of _key.");
  };
  if (debugFlag == true) {
    printf("\nKey generated: '");
  }
  for (i = 0; i < blockSize; ++i) {
    _key[i] = dist1(gen);
    if (debugFlag == true) {
      if (_key[i] != ' ' && (_key[i] < 'A' || _key[i] > 'Z')) {
        printf("%.2x ", (unsigned char)_key[i]);
      } else {
        printf("%c", (unsigned char)_key[i]);
      }
    }
  }
  if (debugFlag == true) {
    printf("'\n");
  }
  return;
}
/******************************************************************************/
void Server::setIV(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  if (_iv == nullptr) {
    _iv = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
    if (_iv == nullptr) {
      throw std::invalid_argument(
          "There was a problem in the memory allocation of _iv.");
    };
  } else {
    _ivV.clear();
  }
  int i;
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  if (debugFlag == true) {
    printf("\nIV generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    if (_firstIv == true || i >= blockSize / 2) {
      _ivV.push_back(_iv[i]);
    } else if (_firstIv == false && i < blockSize / 2) {
      /* nonce set up */
      _iv[i] = dist1(gen);
      _ivV.push_back(_iv[i]);
    }
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)_iv[i]);
    }
  }
  if (_firstIv == true) {
    _firstIv = false;
  }
  if (debugFlag == true) {
    printf("\n\n");
  }
  return;
}
/******************************************************************************/
/* getters */
int Server::getBlockSize() { return _blockSize; }
/******************************************************************************/
unsigned char *Server::getKey() { return _key; }
/******************************************************************************/
unsigned char *Server::getIV() { return _iv; }
/******************************************************************************/
/* this function does the encryption of aes-ctr mode using the iv and key
values, in the end it returns the encrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string Server::aesCtrEncryption(
    const std::vector<unsigned char> &plainTextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *plaintextPointer, *cyphertextPointer;
  bool flag;
  int size, i, j, k = 0, encryptedTextLen, nBlocks, nPop;
  /* work to be done */
  size = plainTextBytesAsciiFullText.size();
  plaintextPointer =
      (unsigned char *)calloc(_blockSize + 1, sizeof(unsigned char));
  if (plaintextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cyperTextPointer'.");
    *b = false;
    return encryptedText;
  }
  cyphertextPointer =
      (unsigned char *)calloc(_blockSize + 1, sizeof(unsigned char));
  if (cyphertextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cypherTextPointer'.");
    *b = false;
    return encryptedText;
  }
  /* nBlocks calc */
  if (plainTextBytesAsciiFullText.size() % _blockSize == 0) {
    nBlocks = plainTextBytesAsciiFullText.size() / _blockSize;
  } else {
    nBlocks = plainTextBytesAsciiFullText.size() / _blockSize + 1;
  }
  for (j = 0; j < nBlocks; ++j, Server::updateIVCtrMode()) {
    /* fill plaintextPointer */
    for (i = 0; i < _blockSize && k < plainTextBytesAsciiFullText.size();
         ++i, ++k) {
      plaintextPointer[i] = plainTextBytesAsciiFullText[i + j * _blockSize];
    }
    /* Encrypt the plaintext */
    encryptedTextLen = Server::aesCtrEncryptWorker(_iv, _blockSize, _key, _iv,
                                                   cyphertextPointer);
    if (debugFlagExtreme == true) {
      std::cout << "Full Decrypted text size = " << encryptedTextLen
                << " bytes." << std::endl;
      BIO_dump_fp(stdout, (const char *)cyphertextPointer, encryptedTextLen);
    }
    for (i = 0; i < _blockSize; ++i) {
      cyphertextPointer[i] ^= plaintextPointer[i];
    }
    /* Add a NULL terminator. We are expecting printable text */
    cyphertextPointer[encryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = Function::appendToVectorFromPointerArray(
        decryptedTextVector, cyphertextPointer, encryptedTextLen);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return encryptedText;
    }
  }
  nPop = decryptedTextVector.size() - plainTextBytesAsciiFullText.size();
  for (j = 0; j < nPop; ++j) {
    decryptedTextVector.pop_back();
  }
  Function::convertVectorBytesToString(decryptedTextVector, encryptedText);
  /* free memory */
  memset(plaintextPointer, 0, _blockSize + 1);
  memset(cyphertextPointer, 0, _blockSize + 1);
  free(plaintextPointer);
  free(cyphertextPointer);
  *b = true;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string Server::aesCtrDecryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *cypherTextPointer, *cypherTextDecryptedPointer;
  bool flag;
  int size, i, j, k = 0, decryptedTextLen, nBlocks, nPop;
  /* work to be done */
  size = encryptedBytesAsciiFullText.size();
  cypherTextPointer =
      (unsigned char *)calloc(_blockSize + 1, sizeof(unsigned char));
  if (cypherTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  cypherTextDecryptedPointer =
      (unsigned char *)calloc(_blockSize + 1, sizeof(unsigned char));
  if (cypherTextDecryptedPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  /* nBlocks calc */
  if (encryptedBytesAsciiFullText.size() % _blockSize == 0) {
    nBlocks = encryptedBytesAsciiFullText.size() / _blockSize;
  } else {
    nBlocks = encryptedBytesAsciiFullText.size() / _blockSize + 1;
  }
  for (j = 0; j < nBlocks; ++j, Server::updateIVCtrMode()) {
    /* fill cyperTextPointer */
    for (i = 0; i < _blockSize && k < encryptedBytesAsciiFullText.size();
         ++i, ++k) {
      cypherTextPointer[i] = encryptedBytesAsciiFullText[i + j * _blockSize];
    }
    /* Decrypt the ciphertext */
    decryptedTextLen = Server::aesCtrDecryptWorker(_iv, _blockSize, _key, _iv,
                                                   cypherTextDecryptedPointer);
    if (debugFlagExtreme == true) {
      std::cout << "Full Decrypted text size = " << decryptedTextLen
                << " bytes." << std::endl;
      BIO_dump_fp(stdout, (const char *)cypherTextDecryptedPointer,
                  decryptedTextLen);
    }
    for (i = 0; i < _blockSize; ++i) {
      cypherTextDecryptedPointer[i] ^= cypherTextPointer[i];
    }
    /* Add a NULL terminator. We are expecting printable text */
    cypherTextDecryptedPointer[decryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = Function::appendToVectorFromPointerArray(
        decryptedTextVector, cypherTextDecryptedPointer, decryptedTextLen);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return decryptedText;
    }
  }
  nPop = decryptedTextVector.size() - encryptedBytesAsciiFullText.size();
  for (j = 0; j < nPop; ++j) {
    decryptedTextVector.pop_back();
  }
  Function::convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  memset(cypherTextPointer, 0, _blockSize + 1);
  memset(cypherTextDecryptedPointer, 0, _blockSize + 1);
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
int Server::aesCtrEncryptWorker(unsigned char *plaintext, int plaintextLen,
                                unsigned char *key, unsigned char *iv,
                                unsigned char *cyphertext) {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int cyphertextLen = 0;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    Server::handleErrors();
  }
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
    Server::handleErrors();
  }
  // EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
    Server::handleErrors();
  }
  cyphertextLen = len;
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
    Server::handleErrors();
  }
  cyphertextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return cyphertextLen;
}
/******************************************************************************/
int Server::aesCtrDecryptWorker(unsigned char *cyphertext, int cypherTextLen,
                                unsigned char *key, unsigned char *iv,
                                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintextLen;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    Server::handleErrors();
  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    Server::handleErrors();
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
    Server::handleErrors();
  plaintextLen = len;
  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
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
    throw std::invalid_argument(
        "Bad 'inputFilePath' | file path cannot be empty");
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
    throw std::invalid_argument(
        "Bad 'inputFilePath' | failed to open the file ");
  } else if (debugFlagExtreme == true) {
    std::cout << "\nThe file 'serverInput.txt' was sucessfully opened.\n"
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
  while (inputFile.good() == true) {
    lineReadBase64.clear();
    lineReadBase64Vector.clear();
    lineReadAsciiVector.clear();
    std::getline(inputFile, lineReadBase64);
    if (lineReadBase64.size() > 0) {
      Function::convertStringToVectorBytes(lineReadBase64,
                                           lineReadBase64Vector);
      b = Function::decodeBase64ToByte(lineReadBase64Vector, base64IndexMap,
                                       lineReadAsciiVector);
      if (b == false) {
        throw std::invalid_argument(
            "There was an error in the function 'decodeBase64ToByte'.");
      }
      Function::convertVectorBytesToString(lineReadAsciiVector, lineReadAscii);
      if (debugFlag == true) {
        std::cout << "Line read (base64): '" << lineReadBase64 << "'"
                  << std::endl;
      }
      if (debugFlag == true) {
        std::cout << "Line read (ascii): '" << lineReadAscii
                  << "' | size = " << lineReadAscii.size() << ".\n"
                  << std::endl;
      }
      /* store the data in the server */
      /* base64 format */
      _stringsBase64.emplace_back(lineReadBase64);
      /* ascii format */
      _stringsAscii.emplace_back(lineReadAscii);
    }
  }
  return;
}
/******************************************************************************/
/* this function will update the iv vector in the counter mode encryption mode,
updating the counter and the nonce accordingly */
void Server::updateIVCtrMode() {
  if (_ctrCounter == ULLONG_MAX) {
    _ctrCounter == 0;
    Server::setIV(_blockSize);
  }
  int i;
  unsigned char *c = (unsigned char *)&_ctrCounter;
  /* update counter */
  ++_ctrCounter;
  /* update IV */
  for (i = _blockSize / 2; i < _blockSize; ++i, ++c) {
    _iv[i] = *c;
    _ivV[i] = *c;
  }
  if (debugFlagExtreme == true) {
    printf("\nIV generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    if (debugFlagExtreme == true) {
      printf("%.2x ", (unsigned char)_iv[i]);
    }
  }
  if (debugFlagExtreme == true) {
    printf("\n\n");
  }
}
/******************************************************************************/
/* this function does the decryption of aes-ctr mode, in the end it returns
the decrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string Server::decryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "Size ciphertext to decrypt: "
              << encryptedBytesAsciiFullText.size() << "'." << std::endl;
  }
  decryptedText = Server::aesCtrDecryption(encryptedBytesAsciiFullText, &flag);
  if (flag == false) {
    *b = false;
  } else {
    *b = true;
  }
  return decryptedText;
}
/******************************************************************************/
/* this function does the encryption of aes-ctr mode, in the end it returns
the encrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string Server::encryption(
    const std::vector<unsigned char> &plaintextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (plaintextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "Size plaintext to encrypt: "
              << plaintextBytesAsciiFullText.size() << "'." << std::endl;
  }
  Server::resetIVCtrMode();
  encryptedText = Server::aesCtrEncryption(plaintextBytesAsciiFullText, &flag);
  if (flag == false) {
    *b = false;
  } else {
    *b = true;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function will encrypt all the inputs already storead into the vector
_stringsEncryptedAscii, the counter in the CTR mode will be reset after each
encryption */
bool Server::encryptInputs() {
  int i, size = _stringsAscii.size();
  std::string encryptedInputLine;
  bool b;
  std::vector<unsigned char> plaintextInputLineV;
  _stringsEncryptedAscii.clear();
  for (i = 0; i < size; ++i) {
    Function::convertStringToVectorBytes(_stringsAscii[i], plaintextInputLineV);
    encryptedInputLine = Server::encryption(plaintextInputLineV, &b);
    if (b == false) {
      perror("There was an error in the function 'encryption'.");
      return false;
    }
    _stringsEncryptedAscii.emplace_back(encryptedInputLine);
  }
  return true;
}
/******************************************************************************/
std::vector<unsigned char> Server::getLineReadInAscii() {
  std::string fullTextRead;
  std::vector<unsigned char> v;
  int i, size = _stringsAscii.size();
  for (i = 0; i < size; ++i) {
    fullTextRead += _stringsAscii[i];
  }
  Function::convertStringToVectorBytes(fullTextRead, v);
  return v;
}
/******************************************************************************/
std::vector<std::string> Server::getStringsAsciiEncrypted() {
  return _stringsEncryptedAscii;
}
/******************************************************************************/
/* this function will reset the iv vector in the counter mode encryption mode,
reseting the counter accordingly */
void Server::resetIVCtrMode() {
  if (_ctrCounter == ULLONG_MAX) {
    _ctrCounter == 0;
    Server::setIV(_blockSize);
  }
  int i;
  unsigned char *c = (unsigned char *)&_ctrCounter;
  /* reset counter */
  _ctrCounter = 0;
  ;
  /* update IV */
  for (i = _blockSize / 2; i < _blockSize; ++i, ++c) {
    _iv[i] = *c;
    _ivV[i] = *c;
  }
  if (debugFlagExtreme == true) {
    printf("\nIV reset generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    if (debugFlagExtreme == true) {
      printf("%.2x ", (unsigned char)_iv[i]);
    }
  }
  if (debugFlagExtreme == true) {
    printf("\n\n");
  }
}
/******************************************************************************/
/* this function will test if the vector decryptedTextV contains the same
content up to strings of size sizeMaxString, having as reference the vector
_stringsAscii, it will return true if they have the same content or false
otherwise */
bool Server::testDecryptedVectorString(std::vector<std::string> decryptedTextV,
                                       const int sizeMaxString) {
  int i, j, size = _stringsAscii.size();
  std::string aux;
  for (i = 0; i < size; ++i) {
    aux.clear();
    aux = decryptedTextV[i].substr(0, sizeMaxString);
    for (j = 0; j < aux.size(); ++j) {
      aux[j] = tolower(aux[j]);
      decryptedTextV[i][j] = tolower(decryptedTextV[i][j]);
    }
    if (aux != decryptedTextV[i]) {
      std::cout << "\nMismatch between: [S]'" << aux << "' and [A]'"
                << decryptedTextV[i] << "'." << std::endl;
      return false;
    }
  }
  return true;
}
/******************************************************************************/
