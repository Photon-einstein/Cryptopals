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
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Server.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string processedInput, veredict;
  bool flag, res;
  std::shared_ptr<Pad> p = std::make_shared<PadPKCS_7>(blockSize);
  std::shared_ptr<Server> s = std::make_shared<Server>(p);
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(s, blockSize);
  flag = s->processInput(";admin=true;", processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  flag = s->testEncryption(processedInput, &res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout << "Normal output | Admin search veredict test with "
               "\";admin=true;\" passed to the server as normal input: "
            << veredict << ".\n\n"
            << std::endl;
  /* perform the attack into CBC mode */
  flag = attacker->attackCBCMode(&res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Function::attackCBCMode'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout << "Attack output | Admin search veredict after the "
               "'attackCBCMode' function: "
            << veredict << "." << std::endl;
  if (res == true) {
    std::cout << "Test passed." << std::endl;
  } else {
    std::cout << "Test failed." << std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
