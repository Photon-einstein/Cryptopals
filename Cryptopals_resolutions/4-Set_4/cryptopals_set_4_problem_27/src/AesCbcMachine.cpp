#include <stdexcept>

#include "./../include/AesCbcMachine.h"
#include "./../include/Function.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"

/* constructor / destructor */
AesCbcMachine::AesCbcMachine(const int blockSize,
                             const std::shared_ptr<Pad> &pad) {
  AesCbcMachine::setBlockSize(blockSize);
  AesCbcMachine::setPad(pad);
  AesCbcMachine::setKey(_blockSize);
  AesCbcMachine::setIV(_blockSize);
}
/******************************************************************************/
AesCbcMachine::~AesCbcMachine() {
  memset(_key, 0, 2 * _blockSize + 1);
  memset(_iv, 0, 2 * _blockSize + 1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* this function does the encryption of aes-ecb mode, in the end it returns
the encrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesCbcMachine::encryption(
    std::vector<unsigned char> &plaintextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (plaintextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  bool flag;
  if (debugFlagExtreme == true) {
    std::cout << "AesEcbMachine log | Size plaintext to encrypt: "
              << plaintextBytesAsciiFullText.size() << "." << std::endl;
  }
  /* pad plaintext before encryption */
  flag = _pad->pad(plaintextBytesAsciiFullText);
  if (flag == false) {
    perror("AesEcbMachine log | There was a problem in the function "
           "'PadPKCS_7::pad()'.");
    *b = false;
    return encryptedText;
  }
  encryptedText =
      AesCbcMachine::aesCbcEncryption(plaintextBytesAsciiFullText, &flag);
  *b = flag;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-ecb mode, in the end it returns
the decrypted text and sets flag b by reference to true if no errors or to
false otherwise */
std::string AesCbcMachine::decryption(
    std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  std::vector<unsigned char> decryptedTextV;
  if (encryptedBytesAsciiFullText.size() == 0) {
    *b = false;
    return decryptedText;
  }
  bool flag;
  decryptedText =
      AesCbcMachine::aesCbcDecryption(encryptedBytesAsciiFullText, &flag);
  if (flag == false) {
    *b = false;
    return decryptedText;
  } else {
    *b = true;
  }
  /* unpad plaintext after decryption */
  Function::convertStringToVectorBytes(decryptedText, decryptedTextV);
  flag = _pad->unpad(decryptedTextV);
  if (flag == false) {
    perror("AesEcbMachine log | There was a problem in the function "
           "'PadPKCS_7::unpad()'.");
    *b = false;
    return decryptedText;
  }
  Function::convertVectorBytesToString(decryptedTextV, decryptedText);
  if (debugFlagExtreme == true) {
    std::cout << "AesEcbMachine log | Size ciphertext decrypted: "
              << decryptedText.size() << " bytes." << std::endl;
  }
  return decryptedText;
}
/******************************************************************************/
/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string AesCbcMachine::aesCbcEncryption(
    const std::vector<unsigned char> &plainTextBytesAsciiFullText, bool *b) {
  std::string encryptedText = "";
  if (b == nullptr) {
    return encryptedText;
  } else if (plainTextBytesAsciiFullText.size() == 0) {
    *b = true;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextBytesAsciiFullTextCopy, cypherTextVector;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  unsigned int size, i, encryptedTextLen,
      size2 = plainTextBytesAsciiFullText.size();
  for (i = 0; i < plainTextBytesAsciiFullText.size(); ++i) {
    plainTextBytesAsciiFullTextCopy.push_back(plainTextBytesAsciiFullText[i]);
  }
  /* pad plaintext before encryption */
  flag = _pad->pad(plainTextBytesAsciiFullTextCopy);
  if (flag == false) {
    perror(
        "AesEcbMachine log | There was an error in the function 'padPKCS_7'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullTextCopy.size();
  /* work to be done */
  plainTextPointer = (unsigned char *)calloc(size + 1, sizeof(unsigned char));
  if (plainTextPointer == nullptr) {
    perror("AesEcbMachine log | There was a problem in the memory allocation "
           "of the 'plainTextPointer'.");
    *b = false;
    return encryptedText;
  }
  encryptedTextPointer =
      (unsigned char *)calloc(size + 1, sizeof(unsigned char));
  if (encryptedTextPointer == nullptr) {
    perror("AesEcbMachine log | There was a problem in the memory allocation "
           "of the 'encryptedTextPointer'.");
    *b = false;
    return encryptedText;
  }
  /* copy content of plainTextVector into plainTextPointer */
  for (i = 0; i < size; ++i) {
    plainTextPointer[i] = plainTextBytesAsciiFullTextCopy[i];
  }
  encryptedTextLen = AesCbcMachine::aesCbcEncryptWorker(
      plainTextPointer, size2, _key, _iv, encryptedTextPointer);
  if (debugFlagExtreme == true) {
    std::cout << "AesEcbMachine log | Full Encrypted ECB text size = "
              << encryptedTextLen << " bytes." << std::endl;
    BIO_dump_fp(stdout, (const char *)encryptedTextPointer, encryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  encryptedTextPointer[encryptedTextLen] = '\0';
  /* fill ciphertext vector */
  flag = Function::fillVectorFromPointerArray(
      cypherTextVector, encryptedTextPointer, encryptedTextLen);
  if (flag == false) {
    perror("\nAesEcbMachine log | There was an error in the function "
           "'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  /* add ciphertext encrypted to the result */
  Function::convertVectorBytesToString(cypherTextVector, encryptedText);
  /* free memory */
  memset(plainTextPointer, 0, size + 1);
  memset(encryptedTextPointer, 0, size + 1);
  free(plainTextPointer);
  free(encryptedTextPointer);
  *b = true;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string AesCbcMachine::aesCbcDecryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0 ||
      encryptedBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> cypherText, decryptedTextVector;
  unsigned char *cypherTextPointer, *cypherTextDecryptedPointer;
  bool flag;
  int nCycles, size, i, decryptedTextLen;
  /* work to be done */
  size = encryptedBytesAsciiFullText.size();
  cypherTextPointer = (unsigned char *)calloc(size + 1, sizeof(unsigned char));
  if (cypherTextPointer == nullptr) {
    perror("AesEcbMachine log | There was a problem in the memory allocation "
           "of the 'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  cypherTextDecryptedPointer =
      (unsigned char *)calloc(size + 1, sizeof(unsigned char));
  if (cypherTextDecryptedPointer == nullptr) {
    perror("AesEcbMachine log | There was a problem in the memory allocation "
           "of the 'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  /* fill cyperTextPointer */
  for (i = 0; i < size; ++i) {
    cypherTextPointer[i] = encryptedBytesAsciiFullText[i];
  }
  /* Decrypt the ciphertext */
  decryptedTextLen = AesCbcMachine::aesCbcDecryptWorker(
      cypherTextPointer, size, _key, _iv, cypherTextDecryptedPointer);
  if (debugFlagExtreme == true) {
    std::cout << "AesEcbMachine log | Full Decrypted text size = "
              << decryptedTextLen << " bytes." << std::endl;
    BIO_dump_fp(stdout, (const char *)cypherTextDecryptedPointer,
                decryptedTextLen);
  }
  /* Add a NULL terminator. We are expecting printable text */
  cypherTextDecryptedPointer[decryptedTextLen] = '\0';
  /* fill ciphertext vector */
  flag = Function::fillVectorFromPointerArray(
      decryptedTextVector, cypherTextDecryptedPointer, decryptedTextLen);
  if (flag == false) {
    perror("\nAesEcbMachine log | There was an error in the function "
           "'fillVectorFromPointerArray'.");
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
void AesCbcMachine::handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}
/******************************************************************************/
int AesCbcMachine::aesCbcEncryptWorker(unsigned char *plaintext,
                                       int plaintextLen, unsigned char *key,
                                       unsigned char *iv,
                                       unsigned char *cyphertext) {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int cyphertextLen = 0;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    AesCbcMachine::handleErrors();
  }
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
    AesCbcMachine::handleErrors();
  }
  // EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, cyphertext, &len, plaintext, plaintextLen)) {
    AesCbcMachine::handleErrors();
  }
  cyphertextLen = len;
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, cyphertext + len, &len)) {
    AesCbcMachine::handleErrors();
  }
  cyphertextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return cyphertextLen;
}
/******************************************************************************/
int AesCbcMachine::aesCbcDecryptWorker(unsigned char *cyphertext,
                                       int cypherTextLen, unsigned char *key,
                                       unsigned char *iv,
                                       unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintextLen = 0;
  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    AesCbcMachine::handleErrors();
  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    AesCbcMachine::handleErrors();
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, cyphertext, cypherTextLen))
    AesCbcMachine::handleErrors();
  plaintextLen = len;
  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    AesCbcMachine::handleErrors();
  plaintextLen += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintextLen;
}
/******************************************************************************/
/* this function should quote out the ";" and "=" characters, and in the end
return the quoted string  */
std::string AesCbcMachine::sanitizeString(std::string input) {
  std::string cleanInput, del = "\\";
  int i, size = input.size();
  /* string sanitization */
  for (i = 0; i < size; ++i) {
    if (input[i] != ';' && input[i] != '=') {
      cleanInput += input[i];
    } else {
      cleanInput += del + input[i];
    }
  }
  return cleanInput;
}
/******************************************************************************/
/* this function will test if the attackersKey matches the AesCbcMachine key's,
it will return true if matches and false otherwise */
bool AesCbcMachine::testKey(std::vector<unsigned char> &attackersKey) {
  if (attackersKey.size() != _blockSize) {
    return false;
  }
  unsigned int i;
  for (i = 0; i < _blockSize; ++i) {
    if (attackersKey[i] != _key[i]) {
      return false;
    }
  }
  return true;
}
/******************************************************************************/
/* setters */
void AesCbcMachine::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "AesCbcMachine log | Bad blockSize: blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void AesCbcMachine::setPad(const std::shared_ptr<Pad> &pad) { _pad = pad; }
/******************************************************************************/
void AesCbcMachine::setKey(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "AesCbcMachine log | Bad blockSize: blockSize cannot be less than 1");
  }
  _key = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (_key == nullptr) {
    throw std::invalid_argument("AesCbcMachine log | There was a problem in "
                                "the memory allocation of _key.");
  };
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 25r inclusive
  int i;
  if (debugFlag == true) {
    printf("\nAesCbcMachine log | Key generated:   ");
  }
  for (i = 0; i < blockSize; ++i) {
    _key[i] = dist1(gen);
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)_key[i]);
    }
  }
  printf("\n");
  _keyFlagDefined = true;
  return;
}
/******************************************************************************/
void AesCbcMachine::setIV(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "AesCbcMachine log | Bad blockSize: blockSize cannot be less than 1");
  }
  _iv = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (_iv == nullptr) {
    throw std::invalid_argument("AesCbcMachine log | There was a problem in "
                                "the memory allocation of _iv.");
  };
  int i;
  if (_keyFlagDefined == false) {
    AesCbcMachine::setKey(_blockSize);
    _keyFlagDefined = true;
  }
  if (debugFlag == true) {
    printf("\nAesCbcMachine log | IV generated:    ");
    for (i = 0; i < blockSize; ++i) {
      _iv[i] = _key[i];
      if (debugFlag == true) {
        printf("%.2x ", (unsigned char)_iv[i]);
      }
    }
    printf("\n\n");
  }
  return;
}
/******************************************************************************/
/* getters */
int AesCbcMachine::getBlockSize() { return _blockSize; }
/******************************************************************************/
unsigned char *AesCbcMachine::getKey() { return _key; }
/******************************************************************************/
unsigned char *AesCbcMachine::getIV() { return _iv; }
/******************************************************************************/
