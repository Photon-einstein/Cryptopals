#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <string>
#include <math.h>
#include <ctype.h>
#include <assert.h>
#include <vector>
#include <iostream>
#include <cstddef>
#include <unordered_map>
#include <bits/stdc++.h>
#include <cctype>
#include <fstream>
#include <random>
#include <map>
#include <algorithm> // for copy() and assign()
#include <iterator> // for back_inserter
#include <memory>

#include "./../include/Function.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Server.h"

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string processedInput, veredict;
  bool flag, res;
  std::shared_ptr<Pad> p = std::make_shared<PadPKCS_7>(blockSize);
  std::shared_ptr<Server> s = std::make_shared<Server>(p);
  flag = s->processInput(";admin=true;", processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  flag = s->testEncryption(processedInput, &res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout<<"Normal output | Admin search veredict test with \";admin=true;\" passed to the server as normal input: "<<veredict<<".\n\n"<<std::endl;
  /* perform the attack into CBC mode */
  flag = Function::attackCBCMode(s, blockSize, &res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Function::attackCBCMode'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout<<"Attack output | Admin search veredict after the 'attackCBCMode' function: "<<veredict<<"."<<std::endl;
  if (res == true) {
    std::cout<<"Test passed."<<std::endl;
  } else {
    std::cout<<"Test failed."<<std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
