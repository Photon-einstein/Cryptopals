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
  const std::string inputFileName =
      "input/cryptopals_set_4_problem_25_dataset.txt";
  const std::string aesEcbKey = "YELLOW SUBMARINE";
  std::shared_ptr<Server> server =
      std::make_shared<Server>(inputFileName, aesEcbKey);
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(server);
  std::string plaintext;
  bool b;
  b = attacker->recoverPlaintextFromServer(plaintext);
  if (b == false) {
    perror("Error at the function 'Attacker::recoverPlaintextFromServer'.");
    exit(1);
  } else {
    std::cout << "\nMain | Test passed, attacker recovered the plaintext from "
                 "the server."
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
