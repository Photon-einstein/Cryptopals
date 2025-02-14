#include <chrono>
#include <stdexcept>
#include <thread>

#include "./../include/AesCtrMachine.h"
#include "./../include/Function.h"

/* constructor / destructor */
AesCtrMachine::AesCtrMachine(const unsigned int blockSize) {
  bool b;
  AesCtrMachine::setBlockSize(blockSize);
  AesCtrMachine::setKey(_blockSize);
  AesCtrMachine::setIV(_blockSize);
}
/******************************************************************************/
AesCtrMachine::~AesCtrMachine() {
  memset(_key, 0, 2 * _blockSize + 1);
  memset(_iv, 0, 2 * _blockSize + 1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* this function does the encryption of aes-ctr mode, in the end it returns
the encrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesCtrMachine::encryption(
    const std::vector<unsigned char> &plaintextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (plaintextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "AesCtrMachine log | size plaintext to encrypt: "
              << plaintextBytesAsciiFullText.size() << "'." << std::endl;
  }
  encryptedText =
      AesCtrMachine::aesCtrEncryption(plaintextBytesAsciiFullText, &flag);
  *b = flag;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-ctr mode, in the end it returns
the decrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesCtrMachine::decryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "AesCtrMachine log | size ciphertext to decrypt: "
              << encryptedBytesAsciiFullText.size() << "'." << std::endl;
  }
  AesCtrMachine::resetIVCtrMode();
  decryptedText =
      AesCtrMachine::aesCtrDecryption(encryptedBytesAsciiFullText, &flag);
  *b = flag;
  return decryptedText;
}
/******************************************************************************/
/* this function does the encryption of aes-ctr mode using the iv and key
values, in the end it returns the encrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string AesCtrMachine::aesCtrEncryption(
    const std::vector<unsigned char> &plainTextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *plaintextPointer, *cyphertextPointer;
  bool flag;
  unsigned int size, i, j, k = 0, encryptedTextLen, nBlocks, nPop;
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
  if (size % _blockSize == 0) {
    nBlocks = size / _blockSize;
  } else {
    nBlocks = size / _blockSize + 1;
  }
  for (j = 0; j < nBlocks; ++j, AesCtrMachine::updateIVCtrMode()) {
    /* fill plaintextPointer */
    for (i = 0; i < _blockSize && k < size; ++i, ++k) {
      plaintextPointer[i] = plainTextBytesAsciiFullText[i + j * _blockSize];
    }
    /* Encrypt the plaintext */
    encryptedTextLen = AesCtrMachine::aesCtrEncryptWorker(
        _iv, _blockSize, _key, _iv, cyphertextPointer);
    if (debugFlagExtreme == true) {
      std::cout << "AesCtrMachine | full decrypted text size = "
                << encryptedTextLen << " bytes." << std::endl;
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
  nPop = decryptedTextVector.size() - size;
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
std::string AesCtrMachine::aesCtrDecryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *cypherTextPointer, *cypherTextDecryptedPointer;
  bool flag;
  unsigned int size, i, j, k = 0, decryptedTextLen, nBlocks, nPop;
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
  if (size % _blockSize == 0) {
    nBlocks = size / _blockSize;
  } else {
    nBlocks = size / _blockSize + 1;
  }
  for (j = 0; j < nBlocks; ++j, AesCtrMachine::updateIVCtrMode()) {
    /* fill cyperTextPointer */
    for (i = 0; i < _blockSize && k < size; ++i, ++k) {
      cypherTextPointer[i] = encryptedBytesAsciiFullText[i + j * _blockSize];
    }
    /* Decrypt the ciphertext */
    decryptedTextLen = AesCtrMachine::aesCtrDecryptWorker(
        _iv, _blockSize, _key, _iv, cypherTextDecryptedPointer);
    if (debugFlagExtreme == true) {
      std::cout << "AesCtrMachine | full decrypted text size = "
                << decryptedTextLen << " bytes." << std::endl;
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
  nPop = decryptedTextVector.size() - size;
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
void AesCtrMachine::handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}
/******************************************************************************/
int AesCtrMachine::aesCtrEncryptWorker(unsigned char *plaintext,
                                       int plaintextLen, unsigned char *key,
                                       unsigned char *iv,
                                       unsigned char *cyphertext) {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int cyphertextLen = 0;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    AesCtrMachine::handleErrors();
  }
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
    AesCtrMachine::handleErrors();
  }
  // EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
    AesCtrMachine::handleErrors();
  }
  cyphertextLen = len;
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
    AesCtrMachine::handleErrors();
  }
  cyphertextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return cyphertextLen;
}
/******************************************************************************/
int AesCtrMachine::aesCtrDecryptWorker(unsigned char *cyphertext,
                                       int cypherTextLen, unsigned char *key,
                                       unsigned char *iv,
                                       unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintextLen;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    AesCtrMachine::handleErrors();
  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    AesCtrMachine::handleErrors();
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
    AesCtrMachine::handleErrors();
  plaintextLen = len;
  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    AesCtrMachine::handleErrors();
  plaintextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintextLen;
}
/******************************************************************************/
/* this function will update the iv vector in the counter mode encryption mode,
updating the counter and the nonce accordingly */
void AesCtrMachine::updateIVCtrMode() {
  if (_ctrCounter == ULLONG_MAX) {
    _ctrCounter = 0;
    AesCtrMachine::setIV(_blockSize);
  }
  unsigned int i;
  unsigned char *c = (unsigned char *)&_ctrCounter;
  /* update counter */
  ++_ctrCounter;
  /* update IV */
  for (i = _blockSize / 2; i < _blockSize; ++i, ++c) {
    _iv[i] = *c;
    _ivV[i] = *c;
  }
  if (debugFlagExtreme == true) {
    printf("AesCtrMachine log | iv generated: ");
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
/* this function will reset the iv vector in the counter mode encryption mode,
reseting the counter accordingly */
void AesCtrMachine::resetIVCtrMode() {
  if (_ctrCounter == ULLONG_MAX) {
    _ctrCounter = 0;
    AesCtrMachine::setIV(_blockSize);
  }
  unsigned int i;
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
    printf("AesCtrMachine log | iv reset generated: ");
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
/* this function will update the iv vector in the counter mode encryption mode,
updating the counter from the _savedCtrCounter value */
void AesCtrMachine::restoreIVCtrMode() {
  unsigned int i;
  unsigned char *c = (unsigned char *)&_ctrCounter;
  /* restore counter */
  _ctrCounter = _savedCtrCounter;
  /* update IV */
  for (i = _blockSize / 2; i < _blockSize; ++i, ++c) {
    _iv[i] = *c;
    _ivV[i] = *c;
  }
  if (debugFlagExtreme == true) {
    printf("AesCtrMachine log | iv restored: ");
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
/* this function will save the value of the _ctrCounter in the auxiliary
variable _savedCtrCounter */
void AesCtrMachine::saveIVCtrMode() {
  _savedCtrCounter = _ctrCounter;
  return;
}
/******************************************************************************/
/* this function will save and then update the _ctrCounter from the new value
passed in the function and then it will update the IV accordingly */
void AesCtrMachine::setIVCtrMode(unsigned long long int newCtrCounter) {
  AesCtrMachine::saveIVCtrMode();
  _ctrCounter = newCtrCounter;
  AesCtrMachine::updateIVCtrMode();
  return;
}
/******************************************************************************/
/* setters */
void AesCtrMachine::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void AesCtrMachine::setKey(const int blockSize) {
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
    printf("AesCtrMachine log | key generated: '");
  }
  for (i = 0; i < blockSize; ++i) {
    _key[i] = dist1(gen);
    if (debugFlag == true) {
      if (i != 0) {
        printf(" ");
      }
      printf("%.2x", (unsigned char)_key[i]);
    }
  }
  if (debugFlag == true) {
    printf("'\n");
  }
  return;
}
/******************************************************************************/
void AesCtrMachine::setIV(const int blockSize) {
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
  unsigned int i;
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  if (debugFlag == true) {
    printf("AesCtrMachine | iv generated: '");
  }
  for (i = 0; i < _blockSize; ++i) {
    if (i >= _blockSize / 2) {
      _ivV.push_back(_iv[i]);
    } else if (i < _blockSize / 2) {
      /* nonce set up */
      _iv[i] = dist1(gen);
      _ivV.push_back(_iv[i]);
      _nonceV.push_back(_iv[i]);
    }
    if (debugFlag == true) {
      if (i != 0) {
        printf(" ");
      }
      printf("%.2x", (unsigned char)_iv[i]);
    }
  }
  if (debugFlag == true) {
    printf("'\n\n");
  }
  if (debugFlagExtreme == true) {
    std::cout << "'.\nAesCtrMachine | nonce: '";
    /* nonce value update */
    for (i = 0; i < _blockSize / 2; ++i) {
      printf("%.2x ", _nonceV[i]);
    }
    printf("'.\n\n");
  }
  return;
}
/******************************************************************************/
/* getters */
int AesCtrMachine::getBlockSize() { return _blockSize; }
/******************************************************************************/
unsigned char *AesCtrMachine::getKey() { return _key; }
/******************************************************************************/
unsigned char *AesCtrMachine::getIV() { return _iv; }
/******************************************************************************/
