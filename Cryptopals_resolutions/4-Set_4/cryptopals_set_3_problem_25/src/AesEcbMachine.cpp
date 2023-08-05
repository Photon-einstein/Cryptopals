#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/AesEcbMachine.h"
#include "./../include/Function.h"

/* constructor / destructor */
AesEcbMachine::AesEcbMachine(const std::string aesEcbKey, const int blockSize) {
  AesEcbMachine::setBlockSize(blockSize);
  AesEcbMachine::setAesEcbKey(aesEcbKey);
  AesEcbMachine::setKey(_blockSize, _aesEcbKey);
  AesEcbMachine::setIV(_blockSize);
  AesEcbMachine::setAesEcbKey(aesEcbKey);
}
/******************************************************************************/
AesEcbMachine::~AesEcbMachine() {
  memset(_key, 0, 2*_blockSize+1);
  memset(_iv, 0, 2*_blockSize+1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* setters */
void AesEcbMachine::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void AesEcbMachine::setKey(const int blockSize, const std::string key) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  unsigned int i;
  _key = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  if (_key == nullptr) {
    throw std::invalid_argument("There was a problem in the memory allocation of _key.");
  };
  for (i = 0; i < static_cast<unsigned int>(blockSize) && i < key.size(); ++i) {
    _key[i] = key[i];
  }
  return;
}
/******************************************************************************/
void AesEcbMachine::setIV(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  if (_iv == nullptr) {
    _iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
    if (_iv == nullptr) {
      throw std::invalid_argument("There was a problem in the memory allocation of _iv.");
    };
  }
  return;
}
/******************************************************************************/
void AesEcbMachine::setAesEcbKey(const std::string aesEcbKey) {
  _aesEcbKey = aesEcbKey;
}
/******************************************************************************/
/* getters */
int AesEcbMachine::getBlockSize() {
  return _blockSize;
}
/******************************************************************************/
unsigned char* AesEcbMachine::getKey() {
  return _key;
}
/******************************************************************************/
unsigned char* AesEcbMachine::getIV() {
  return _iv;
}
/******************************************************************************/
std::string AesEcbMachine::getAesEcbKey() {
  return _aesEcbKey;
}
/******************************************************************************/
/* this function does the encryption of aes-ecb mode using the iv and key values,
in the end it returns the encrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string AesEcbMachine::aesEcbEncryption(const std::vector<unsigned char> &plainTextBytesAsciiFullText,
    bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> cipherTextV;
  unsigned char *plaintextPointer, *cyphertextPointer;
  bool flag;
  int size, i, encryptedTextLen;
  /* work to be done */
  size = plainTextBytesAsciiFullText.size();
  plaintextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (plaintextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cyperTextPointer'.");
    *b = false;
    return encryptedText;
  }
  cyphertextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (cyphertextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cypherTextPointer'.");
    *b = false;
    return encryptedText;
  }
  for (i = 0; i < size; ++i) {
    plaintextPointer[i] = plainTextBytesAsciiFullText[i];
  }
  /* Encrypt the plaintext */
  encryptedTextLen = AesEcbMachine::aesEcbEncryptWorker(plaintextPointer, size,
  _key, _iv, cyphertextPointer);
  if (debugFlagExtreme == true) {
    std::cout<<"AesEcbMachine log | full encrypted text size = "<<encryptedTextLen<<" bytes."<<std::endl;
    BIO_dump_fp (stdout, (const char *)cyphertextPointer, encryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  cyphertextPointer[encryptedTextLen] = '\0';
  flag = Function::fillVectorFromPointerArray(cipherTextV, cyphertextPointer, encryptedTextLen+1);
  if (flag == false) {
    perror("There was a problem in the memory allocation of the 'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  Function::convertVectorBytesToString(cipherTextV, encryptedText);
  /* free memory */
  memset(plaintextPointer, 0, size+1);
  memset(cyphertextPointer, 0, size+1);
  free(plaintextPointer);
  free(cyphertextPointer);
  *b = true;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key values,
in the end it returns the decrypted text and sets flag b by reference to true if
no errors or to false otherwise */
std::string AesEcbMachine::aesEcbDecryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> decryptedTextVector;
  unsigned char *ciphertextPointer, *ciphertextDecryptedPointer;
  bool flag;
  int size, i, decryptedTextLen;
  /* work to be done */
  size = encryptedBytesAsciiFullText.size();
  ciphertextPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (ciphertextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  ciphertextDecryptedPointer = (unsigned char*) calloc(size+1, sizeof (unsigned char));
  if (ciphertextDecryptedPointer == nullptr) {
    perror("There was a problem in the memory allocation of the 'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  /* fill cyperTextPointer */
  for (i = 0; i < size; ++i) {
    ciphertextPointer[i] = encryptedBytesAsciiFullText[i];
  }
  /* Decrypt the ciphertext */
  decryptedTextLen = AesEcbMachine::aesEcbDecryptWorker(ciphertextPointer, size,
  _key, _iv, ciphertextDecryptedPointer);
  if (debugFlagExtreme == true) {
    std::cout<<"AesEcbMachine log | full decrypted text size = "<<decryptedTextLen<<" bytes."<<std::endl;
    BIO_dump_fp (stdout, (const char *)ciphertextDecryptedPointer, decryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  ciphertextDecryptedPointer[decryptedTextLen] = '\0';
  flag = Function::fillVectorFromPointerArray(decryptedTextVector, ciphertextDecryptedPointer, decryptedTextLen+1);
  if (flag == false) {
    perror("There was a problem in the memory allocation of the 'fillVectorFromPointerArray'.");
    *b = false;
    return decryptedText;
  }
  Function::convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  memset(ciphertextPointer, 0, size+1);
  memset(ciphertextDecryptedPointer, 0, size+1);
  free(ciphertextPointer);
  free(ciphertextDecryptedPointer);
  *b = true;
  return decryptedText;
}
/******************************************************************************/
void AesEcbMachine::handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
/******************************************************************************/
int AesEcbMachine::aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen, unsigned char *key,
    unsigned char *iv, unsigned char *cyphertext) {
  EVP_CIPHER_CTX *ctx;
  int len=0;
  int cyphertextLen=0;
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
      AesEcbMachine::handleErrors();
  }
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
      AesEcbMachine::handleErrors();
  }
  //EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
      AesEcbMachine::handleErrors();
  }
  cyphertextLen = len;
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
      AesEcbMachine::handleErrors();
  }
  cyphertextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return cyphertextLen;
}
/******************************************************************************/
int AesEcbMachine::aesEcbDecryptWorker(unsigned char *cyphertext, int cypherTextLen, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintextLen;
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
      AesEcbMachine::handleErrors();
  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
      AesEcbMachine::handleErrors();
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
      AesEcbMachine::handleErrors();
  plaintextLen = len;
  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
      AesEcbMachine::handleErrors();
  plaintextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintextLen;
}
/******************************************************************************/
/* this function does the encryption of aes-ecb mode, in the end it returns
the encrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesEcbMachine::encryption(const std::vector<unsigned char> &plaintextBytesAsciiFullText,
    bool *b) {
  std::string encryptedText;
  if (plaintextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout<<"AesEcbMachine log | size plaintext to encrypt: "<<plaintextBytesAsciiFullText.size()<<"."<<std::endl;
  }
  encryptedText = AesEcbMachine::aesEcbEncryption(plaintextBytesAsciiFullText, &flag);
  *b = flag;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-ecb mode, in the end it returns
the decrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesEcbMachine::decryption(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  bool flag;
  decryptedText = AesEcbMachine::aesEcbDecryption(encryptedBytesAsciiFullText, &flag);
  if (flag == false) {
    *b = false;
  } else {
    *b = true;
  }
  std::cout<<"AesEcbMachine log | size ciphertext decrypted: "<<encryptedBytesAsciiFullText.size()<<" bytes."<<std::endl;
  return decryptedText;
}
/******************************************************************************/
