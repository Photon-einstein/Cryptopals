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
#include "./../include/Server.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  bool b;
  std::shared_ptr<Server> server =
      std::make_shared<Server>("input/serverInput.txt");
  std::vector<unsigned char> fullCyphertextReadV = server->getLineReadInAscii();
  std::string decryptedText = server->decryption(fullCyphertextReadV, &b);
  std::string encryptedText, cyphertextTest;
  std::vector<unsigned char> fullplaintextReadV;
  if (b == false) {
    perror("There was an error in the function 'Decryption'.");
    return false;
  }
  std::cout << "Decrypted Text (CTR mode): '" << decryptedText << "'."
            << std::endl;
  Function::convertStringToVectorBytes(decryptedText, fullplaintextReadV);
  encryptedText = server->encryption(fullplaintextReadV, &b);
  if (b == false) {
    perror("There was an error in the function 'Encryption'.");
    return false;
  }
  Function::convertVectorBytesToString(fullCyphertextReadV, cyphertextTest);
  if (encryptedText == cyphertextTest) {
    std::cout
        << "Encryption and decryption in counter mode are working correctly."
        << std::endl;
  } else {
    std::cout
        << "Encryption and decryption in counter mode are working incorrectly."
        << std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
