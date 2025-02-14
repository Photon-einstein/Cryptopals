#include <stdexcept>

#include "./../include/Function.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Server.h"

/* constructor / destructor */
Server::Server(const std::shared_ptr<Pad> &pad) {
  Server::setBlockSize(blockSize);
  Server::setPad(pad);
  Server::setKey(_blockSize);
  Server::setIV(_blockSize);
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
void Server::setPad(const std::shared_ptr<Pad> &pad) { _pad = pad; }
/******************************************************************************/
void Server::setKey(const int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  _key = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (_key == nullptr) {
    throw std::invalid_argument(
        "There was a problem in the memory allocation of _key.");
  };
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 25r inclusive
  int i;
  if (debugFlag == true) {
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
    throw std::invalid_argument(
        "Bad blockSize | blockSize cannot be less than 1");
  }
  _iv = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (_iv == nullptr) {
    throw std::invalid_argument(
        "There was a problem in the memory allocation of _iv.");
  };
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 25r inclusive
  int i;
  if (debugFlag == true) {
    printf("\nIV generated: ");
  }
  for (i = 0; i < blockSize; ++i) {
    _iv[i] = dist1(gen);
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)_iv[i]);
    }
  }
  printf("\n");
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
/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string Server::aesCbcEncryption(
    const std::vector<unsigned char> &plainTextBytesAsciiFullText,
    unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string encryptedText;
  if (plainTextBytesAsciiFullText.size() == 0) {
    *b = false;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextBytesAsciiFullTextCopy;
  std::vector<unsigned char> previousCypherTextVector, plainTextVector, xorRes,
      cypherTextVector;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  int nCycles, size, i, j, encryptedTextLen;
  for (i = 0; i < plainTextBytesAsciiFullText.size(); ++i) {
    plainTextBytesAsciiFullTextCopy.push_back(plainTextBytesAsciiFullText[i]);
  }
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
  flag = Function::fillVectorFromPointerArray(previousCypherTextVector, iv,
                                              blockSize);
  if (flag == false) {
    perror(
        "\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return encryptedText;
  }
  /* padd plaintext before encryption */
  flag = _pad->pad(plainTextBytesAsciiFullTextCopy);
  if (flag == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullTextCopy.size();
  nCycles = size / blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)blockSize; ++j) {
      plainTextVector.push_back(
          plainTextBytesAsciiFullTextCopy[blockSize * i + j]);
    }
    /* previous cyphertext XOR plainText */
    flag = Function::xorFunction(previousCypherTextVector, plainTextVector,
                                 xorRes);
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
    if (debugFlagExtreme == true) {
      std::cout << "Round encrypted text size = " << encryptedTextLen
                << std::endl;
    }
    /* Add a NULL terminator. We are expecting printable text */
    encryptedTextPointer[encryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = Function::fillVectorFromPointerArray(
        cypherTextVector, encryptedTextPointer, encryptedTextLen);
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
    flag = Function::fillVectorFromPointerArray(
        previousCypherTextVector, encryptedTextPointer, blockSize);
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
    std::cout << "Full encrypted text size = " << encryptedText.size()
              << std::endl;
  }
  *b = true;
  return encryptedText;
}
/******************************************************************************/
/* this function does the decryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string Server::aesCbcDecryption(
    const std::vector<unsigned char> &encryptedBytesAsciiFullText,
    unsigned int blockSize, unsigned char *key, unsigned char *iv, bool *b) {
  std::string decryptedText;
  if (encryptedBytesAsciiFullText.size() == 0 ||
      encryptedBytesAsciiFullText.size() % blockSize != 0) {
    *b = false;
    return decryptedText;
  }
  std::vector<unsigned char> decryptedTextVector;
  std::vector<unsigned char> previousCypherText, cypherText, xorRes;
  unsigned char *cypherTextPointer, *decryptedTextPointer,
      *cypherTextDecryptedPointer;
  bool flag;
  int nCycles, size, i, j, decryptedTextLen;
  /* work to be done */
  cypherTextPointer =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (cypherTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cyperTextPointer'.");
    *b = false;
    return decryptedText;
  }
  decryptedTextPointer =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (decryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'decryptedTextPointer'.");
    *b = false;
    return decryptedText;
  }
  cypherTextDecryptedPointer =
      (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (cypherTextDecryptedPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'cypherTextDecryptedPointer'.");
    *b = false;
    return decryptedText;
  }
  flag =
      Function::fillVectorFromPointerArray(previousCypherText, iv, blockSize);
  if (flag == false) {
    perror(
        "\nThere was an error in the function 'fillVectorFromPointerArray'.");
    *b = false;
    return decryptedText;
  }
  size = encryptedBytesAsciiFullText.size();
  nCycles = size / blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill cyperTextPointer */
    for (j = 0; j < (int)blockSize; ++j) {
      cypherTextPointer[j] = encryptedBytesAsciiFullText[blockSize * i + j];
    }
    /* Decrypt the ciphertext */
    decryptedTextLen = Server::aesEcbDecryptWorker(
        cypherTextPointer, blockSize, key, iv, cypherTextDecryptedPointer);
    if (debugFlagExtreme == true) {
      std::cout << "Round decrypted text size = " << decryptedTextLen
                << std::endl;
    }
    /* Add a NULL terminator. We are expecting printable text */
    cypherTextDecryptedPointer[decryptedTextLen] = '\0';
    /* fill cyphertext vector */
    flag = Function::fillVectorFromPointerArray(
        cypherText, cypherTextDecryptedPointer, decryptedTextLen);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return decryptedText;
    }
    /* previous cyphertext XOR Decrypted CypherText */
    flag = Function::xorFunction(previousCypherText, cypherText, xorRes);
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
    flag = Function::fillVectorFromPointerArray(previousCypherText,
                                                cypherTextPointer, blockSize);
    if (flag == false) {
      perror(
          "\nThere was an error in the function 'fillVectorFromPointerArray'.");
      *b = false;
      return decryptedText;
    }
  }
  /* we need to unpad the decrypted text */
  Function::convertStringToVectorBytes(decryptedText, decryptedTextVector);
  flag = _pad->unpad(decryptedTextVector);
  if (flag == false) {
    perror("There was an error in the function 'unpadPKCS_7'.");
    *b = false;
    return decryptedText;
  }
  Function::convertVectorBytesToString(decryptedTextVector, decryptedText);
  /* free memory */
  free(cypherTextPointer);
  free(decryptedTextPointer);
  free(cypherTextDecryptedPointer);
  if (debugFlag == true) {
    std::cout << "Full decrypted text size = " << decryptedText.size()
              << std::endl;
  }
  *b = true;
  return decryptedText;
}
/******************************************************************************/
void Server::handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}
/******************************************************************************/
int Server::aesEcbEncryptWorker(unsigned char *plaintext, int plaintextLen,
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
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) {
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
int Server::aesEcbDecryptWorker(unsigned char *cyphertext, int cypherTextLen,
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
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
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
/* this function receives some data, it will prepend with the content
"comment1=cooking%20MCs;userdata=" and append with the following content
";comment2=%20like%20a%20pound%20of%20bacon", it should quote out the ";"
and "=" characters, then it will encrypt that data using AES cbc mode, and
return that data using inputProcessed, it will return true if all ok or false
otherwise */
bool Server::processInput(std::string data, std::string &inputProcessed) {
  std::string processedData;
  std::string encryptedString;
  std::vector<unsigned char> plainTextBytesAsciiFullText;
  bool flag;
  /* clear inputProcessed string */
  inputProcessed.clear();
  processedData = "comment1=cooking%20MCs;userdata=";
  std::string dataCleaned = Server::sanitizeString(data);
  processedData += dataCleaned + ";comment2=%20like%20a%20pound%20of%20bacon";
  if (debugFlag == true) {
    std::cout << "\nData: '" << data << "' processed becomes: '" << dataCleaned
              << "'." << std::endl;
    std::cout << "\nProcessed input: '" << processedData
              << "', size = " << processedData.size() << "." << std::endl;
  }
  Function::convertStringToVectorBytes(processedData,
                                       plainTextBytesAsciiFullText);
  encryptedString = aesCbcEncryption(plainTextBytesAsciiFullText, _blockSize,
                                     _key, _iv, &flag);
  if (flag == false) {
    perror("\nThere was an error in the function 'aesCbcEncryption'.");
    return false;
  }
  /* pass data to the call object */
  inputProcessed = encryptedString;
  return true;
}
/******************************************************************************/
/* this function should quote out the ";" and "=" characters, and in the end
return the quoted string  */
std::string Server::sanitizeString(std::string input) {
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
/* this function will decrypt the string using AES ecb mode, then it will
test for the substring ";admin=true", if it finds it will return true by
reference in res or false otherwise. If all went ok it will return true,
false otherwise */
bool Server::testEncryption(const std::string &encryption, bool *res) {
  if (encryption.size() % _blockSize != 0 || res == nullptr) {
    perror("\nThere was an error in the function 'testEncryption'.");
    return false;
  }
  std::string decryptedText;
  std::vector<unsigned char> encryptedBytesAsciiFullText;
  bool flag;
  size_t found;
  int i;
  Function::convertStringToVectorBytes(encryption, encryptedBytesAsciiFullText);
  decryptedText = Server::aesCbcDecryption(encryptedBytesAsciiFullText,
                                           _blockSize, _key, _iv, &flag);
  if (flag == false) {
    perror("\nThere was an error in the function 'aesCbcDecryption'.");
    return false;
  }
  found = decryptedText.find(";admin=true");
  /* passing finals valus to the calling object */
  *res = (found != std::string::npos) ? true : false;
  std::cout << "Decrypted text: '" << decryptedText << ".\n" << std::endl;
  return true;
}
/******************************************************************************/
