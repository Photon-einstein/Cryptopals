#include <stdexcept>

#include "./../include/Function.h"
#include "./../include/RandomPrefixWorker.h"

/* constructor / destructor */
RandomPrefixWorker::RandomPrefixWorker(int blockSize, bool debugFlag,
                                       bool debugFlagExtreme, std::string key,
                                       std::string iv) {
  if (blockSize < 1) {
    throw std::invalid_argument("block size must be positive.");
  } else if (key.size() != blockSize) {
    throw std::invalid_argument(
        "key must be of the same size as the blockSize.");
  } else if (iv.size() != blockSize) {
    throw std::invalid_argument(
        "iv must be of the same size as the blockSize.");
  }
  _blockSize = blockSize;
  RandomPrefixWorker::setDebugFlag(debugFlag);
  RandomPrefixWorker::setRandomPrefixSize();
  RandomPrefixWorker::setKey(key);
  RandomPrefixWorker::setIV(iv);
}
/******************************************************************************/
RandomPrefixWorker::~RandomPrefixWorker() {
  memset(_key, 0, 2 * _blockSize + 1);
  memset(_iv, 0, 2 * _blockSize + 1);
  free(_key);
  free(_iv);
  _key = nullptr;
  _iv = nullptr;
}
/******************************************************************************/
/* this function returns true if the guess of the random prefix size
is equal to the randomPrefixSize, false otherwise */
bool RandomPrefixWorker::testRandomPrefixSize(int randomPrefixSizeGuess) {
  if (randomPrefixSizeGuess == _randomPrefixSize) {
    return true;
  } else {
    return false;
  }
}
/******************************************************************************/
/* setters */
void RandomPrefixWorker::setRandomPrefixSize() {
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      1, _blockSize); // distribute results between 1 and _blockSize inclusive
  if (_debugFlag == true) {
    printf("\nRandom prefix size: ");
  }
  _randomPrefixSize = dist1(gen);
  if (_debugFlag == true) {
    printf("%d.\n", _randomPrefixSize);
  }
  return;
}
/******************************************************************************/
void RandomPrefixWorker::setKey(std::string key) {
  int i, size = key.size();
  if (size > _blockSize) {
    size = _blockSize;
  }
  _key = (unsigned char *)calloc(2 * _blockSize + 1, sizeof(unsigned char));
  if (_key == nullptr) {
    perror("There was a problem in the memory allocation of _key.");
    return;
  }
  for (i = 0; i < size; ++i) {
    _key[i] = key[i];
  }
  return;
}
/******************************************************************************/
void RandomPrefixWorker::setIV(std::string iv) {
  int i, size = iv.size();
  if (size > _blockSize) {
    size = _blockSize;
  }
  _iv = (unsigned char *)calloc(2 * _blockSize + 1, sizeof(unsigned char));
  if (_iv == nullptr) {
    perror("There was a problem in the memory allocation of _iv.");
    return;
  }
  for (i = 0; i < size; ++i) {
    _iv[i] = iv[i];
  }
  return;
}
/******************************************************************************/
void RandomPrefixWorker::setDebugFlag(bool debugFlag) {
  _debugFlag = debugFlag;
  return;
}
/******************************************************************************/
void RandomPrefixWorker::setDebugFlagExtreme(bool debugFlagExtreme) {
  _debugFlagExtreme = debugFlagExtreme;
  return;
}
/******************************************************************************/
/* getters */
int RandomPrefixWorker::getBlockSize() { return _blockSize; };
/******************************************************************************/
bool RandomPrefixWorker::getDebugFlag() { return _debugFlag; }
/******************************************************************************/
bool RandomPrefixWorker::getDebugFlagExtreme() { return _debugFlagExtreme; }
/******************************************************************************/
/* this function does the encryption of aes-cbc mode using the iv and key
values, in the end it returns the decrypted text and sets flag b by reference to
true if no errors or to false otherwise */
std::string RandomPrefixWorker::aesEcbEncryption(
    const std::vector<unsigned char> &plainTextBytesAsciiFullText, bool *b) {
  std::string encryptedText;
  if (b == nullptr) {
    return encryptedText;
  } else if (plainTextBytesAsciiFullText.size() == 0) {
    *b = true;
    return encryptedText;
  }
  std::vector<unsigned char> plainTextBytesAsciiFullTextCopy;
  std::vector<unsigned char> plainTextVector, cypherTextVector, randomPrefix;
  unsigned char *plainTextPointer, *encryptedTextPointer;
  bool flag;
  int nCycles, size, i, j, encryptedTextLen;
  for (i = 0; i < plainTextBytesAsciiFullText.size(); ++i) {
    plainTextBytesAsciiFullTextCopy.push_back(plainTextBytesAsciiFullText[i]);
  }
  /* work to be done */
  plainTextPointer =
      (unsigned char *)calloc(2 * _blockSize + 1, sizeof(unsigned char));
  if (plainTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'plainTextPointer'.");
    *b = false;
    return encryptedText;
  }
  encryptedTextPointer =
      (unsigned char *)calloc(2 * _blockSize + 1, sizeof(unsigned char));
  if (encryptedTextPointer == nullptr) {
    perror("There was a problem in the memory allocation of the "
           "'encryptedTextPointer'.");
    *b = false;
    return encryptedText;
  }
  /* add random prefix into plaintext */
  randomPrefix = RandomPrefixWorker::generateRandomPrefix();
  for (i = 0; i < plainTextBytesAsciiFullTextCopy.size(); ++i) {
    randomPrefix.push_back(plainTextBytesAsciiFullTextCopy[i]);
  }
  plainTextBytesAsciiFullTextCopy.clear();
  for (i = 0; i < randomPrefix.size(); ++i) {
    plainTextBytesAsciiFullTextCopy.push_back(randomPrefix[i]);
  }
  /* padd plaintext before encryption */
  flag = Function::padPKCS_7(plainTextBytesAsciiFullTextCopy, _blockSize);
  if (flag == false) {
    perror("There was an error in the function 'padPKCS_7'.");
    *b = false;
    return encryptedText;
  }
  size = plainTextBytesAsciiFullTextCopy.size();
  nCycles = size / _blockSize;
  for (i = 0; i < nCycles; ++i) {
    /* fill plainTextPointer */
    plainTextVector.clear();
    for (j = 0; j < (int)_blockSize; ++j) {
      plainTextVector.push_back(
          plainTextBytesAsciiFullTextCopy[_blockSize * i + j]);
    }
    /* copy content of plainTextVector into plainTextPointer */
    for (j = 0; j < (int)_blockSize; ++j) {
      plainTextPointer[j] = plainTextVector[j];
    }
    memset(encryptedTextPointer, 0, 2 * _blockSize + 1);
    /* Decrypt the ciphertext */
    encryptedTextLen = Function::aesEcbEncryptWorker(
        plainTextPointer, _blockSize, _key, _iv, encryptedTextPointer);
    if (debugFlagExtreme == true) {
      std::cout << "Full Decrypted ECB text size = " << encryptedTextLen
                << std::endl;
      BIO_dump_fp(stdout, (const char *)encryptedTextPointer, encryptedTextLen);
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
  }
  /* free memory */
  free(plainTextPointer);
  free(encryptedTextPointer);
  if (debugFlagExtreme == true) {
    std::cout << "Full Encrypted text size = " << encryptedText.size()
              << std::endl;
  }
  return encryptedText;
}
/******************************************************************************/
/* this function generates a random prefix of size _randomPrefixSize and it
returns a string of that size filled with random data */
std::vector<unsigned char> RandomPrefixWorker::generateRandomPrefix() {
  std::random_device rd;  // non-deterministic generator
  std::mt19937 gen(rd()); // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(
      0, 255); // distribute results between 0 and 255 inclusive
  std::vector<unsigned char> randomPrefix;
  int i;
  if (_debugFlagExtreme == true) {
    printf("\nRandom prefix: ");
  }
  for (i = 0; i < _randomPrefixSize; ++i) {
    randomPrefix.push_back(dist1(gen));
    if (_debugFlagExtreme == true) {
      printf("%.2x ", randomPrefix[i]);
    }
  }
  if (_debugFlagExtreme == true) {
    printf("\n");
  }
  return randomPrefix;
}
/******************************************************************************/
