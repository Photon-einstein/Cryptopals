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
#include "./../include/MT19937.h"
#include "./../include/Server.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::shared_ptr<Server> server = std::make_shared<Server>();
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(server);
  std::vector<unsigned char> eV =
      server->encryptWithStreamCypherBasedOnMt19937();
  bool b;
  unsigned int seed;
  std::string plaintextDecrypted =
      server->decryptWithStreamCypherBasedOnMt19937(eV);
  printf("Plaintext decrypted (server test): '");
  fflush(NULL);
  std::cout << plaintextDecrypted << "'" << std::endl;
  b = attacker->recoverTheKeyFromTheServer(seed);
  if (b == false) {
    perror("There was a problem in the function "
           "'Attacker::recoverTheKeyFromTheServer'.");
  }
  b = attacker->performTestsAgainstServer();
  if (b == false) {
    perror("There was a problem in the function "
           "'Attacker::performTestsAgainstServer'.");
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
