#include <algorithm> // for copy() and assign()
#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <cstddef>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <iterator> // for back_inserter
#include <map>
#include <math.h>
#include <memory>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

#include "./../include/Function.h"
#include "./../include/RandomPrefixWorker.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  bool flag;
  std::string encryptionMode,
      inputFileName = "input/cryptopals_set_2_problem_14_dataset.txt";
  std::string encryptedText, decryptedTextString, unknownString;
  std::vector<unsigned char> unknownStringV, knownStringV, plaintextFullVector;
  std::vector<unsigned char> encryptedTextV;
  std::map<std::string, int> dictionary;
  int blockSizeCalculated = 0;
  std::shared_ptr<RandomPrefixWorker> randomPrefixWork;
  unsigned char *keyV;
  unsigned char *iv;
  size_t i;
  std::string ivString, key;
  int sizeRandomPrefixGuess = 0;
  /* iv fulling */
  for (i = 0; i < blockSize; ++i) {
    ivString += (char)0;
  }
  /* step 1: key generation */
  flag = Function::keyFilling(blockSize, key);
  if (flag == false) {
    perror("\nThere was an error in the function 'keyFilling'.");
    exit(1);
  }
  /* step 2: assert ECB encryption mode is used */
  flag = Function::encryptionOracleWrapper(blockSize, encryptionMode);
  if (flag == false) {
    perror("There was a problem in the function 'encryptionOracleWrapper'.");
    exit(1);
  } else if (encryptionMode != "ECB") {
    perror("The encryption scheme used is not ECB mode.");
    exit(1);
  } else {
    std::cout << "\nEncryption oracle veredict: 'ECB' encryption mode is being "
                 "used.\n"
              << std::endl;
  }
  /* step 3: read file content and convert to ascii, then return in vector */
  flag = Function::getDecodeDataFromFile(inputFileName, unknownStringV);
  if (flag == false) {
    perror("There was a problem in the function 'getDecodeDataFromFile'.");
    exit(1);
  }
  /* step 4: detect the block size of the block cypher */
  flag = Function::getBlockCypherSize(blockSizeCalculated);
  if (flag == false) {
    perror("There was a problem in the function 'getBlockCypherSize'.");
    exit(1);
  } else if (blockSizeCalculated == -1) {
    printf("The function 'getBlockCypherSize' could not find a valid block "
           "size up to %d bytes.",
           maxBlockSize);
    exit(1);
  } else {
    std::cout << "Block size calculated: " << blockSizeCalculated << " bytes / "
              << blockSizeCalculated * 8 << " bits." << std::endl;
  }
  /* allocate the smart pointer with the RandomPrefixWorker object */
  randomPrefixWork = std::make_shared<RandomPrefixWorker>(
      blockSize, debugFlag, debugFlagExtreme, key, ivString);
  if (randomPrefixWork.get() == nullptr) {
    perror("The memory allocation failed at the shared_ptr.");
    exit(1);
  }
  /* step 5: guess the size of the random prefix */
  flag = Function::guessSizeRandomPrefix(randomPrefixWork,
                                         sizeRandomPrefixGuess, blockSize);
  if (flag == false) {
    perror("There was a problem in the function 'guessSizeRandomPrefix'.");
    exit(1);
  } else if (randomPrefixWork->testRandomPrefixSize(sizeRandomPrefixGuess) ==
             true) {
    printf("\nThe function 'guessSizeRandomPrefix' correctly estimated the "
           "size of the random prefix used in AES ecb mode as %d bytes.\n",
           sizeRandomPrefixGuess);
  } else {
    printf("\nThe function 'guessSizeRandomPrefix' failed estimated the size "
           "of the random prefix used in AES ecb mode, stating %d bytes.\n",
           sizeRandomPrefixGuess);
  }
  /* stage 6.1: prepare keyV and iv for later on do the */
  keyV = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  iv = (unsigned char *)calloc(2 * blockSize + 1, sizeof(unsigned char));
  if (keyV == nullptr || iv == nullptr) {
    perror("There was a problem in the memory allocation.");
    exit(1);
  }
  for (i = 0; i < key.size(); ++i) {
    keyV[i] = key[i];
  }
  /* step 6.2: decrypt the encrypted message */
  /* decrypt byte, one at a time */
  Function::convertVectorBytesToString(unknownStringV, unknownString);
  flag = Function::decryptText(unknownStringV, blockSize, decryptedTextString,
                               randomPrefixWork, sizeRandomPrefixGuess);
  if (flag == false) {
    printf("\nThere was a problem in the function 'decryptText'.");
    fflush(NULL);
    exit(1);
  }
  std::cout << "\n\nDecrypted text: \n'" << decryptedTextString << "'."
            << std::endl;
  if (unknownString == decryptedTextString) {
    std::cout << "\nECB decryption test passed." << std::endl;
  } else {
    std::cout << "\nECB decryption test failed." << std::endl;
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
