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

#include "./../include/Attacker.h"
#include "./../include/Function.h"
#include "./../include/Server.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::shared_ptr<Server> server =
      std::make_shared<Server>("input/serverInput.txt");
  std::shared_ptr<Attacker> attacker =
      std::make_shared<Attacker>(server, blockSize);
  std::vector<std::string> decryptedStrings;
  std::string resS;
  int sizeKey;
  bool b;
  int i;
  server->encryptInputs();
  b = attacker->decryptMinSizeEncryptedStrings(decryptedStrings, &sizeKey);
  if (b == false) {
    perror(
        "There was an error in the function 'decryptMinSizeEncryptedStrings'.");
    return false;
  }
  std::cout << "\n\nDecrypted strings by the attacker: " << std::endl;
  for (i = 0; i < (int)decryptedStrings.size(); ++i) {
    std::cout << decryptedStrings[i] << std::endl;
  }
  b = server->testDecryptedVectorString(decryptedStrings, sizeKey);
  resS = (b == true) ? "true" : "false";
  std::cout << "\n\n####  Server veredict on the presence of this strings at "
               "the server: "
            << resS << "." << std::endl;
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
