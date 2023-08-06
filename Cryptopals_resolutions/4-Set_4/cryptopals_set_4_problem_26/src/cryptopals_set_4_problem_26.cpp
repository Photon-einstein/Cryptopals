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

#include "./../include/Server.h"
#include "./../include/Attacker.h"
#include "./../include/Function.h"

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::shared_ptr<Server> server = std::make_shared<Server>();
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(server);
  std::string veredict, processedInput;
  std::cout<<"Main log | normal path, without attack."<<std::endl;
  bool res, flag = server->processInput(";admin=true;", processedInput);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  /* test adding of plain ";admin=true;" into the plaintext */
  flag = server->testEncryption(processedInput, &res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Server::processInput'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout<<"Main log | Normal output: Admin search veredict test with \";admin=true;\" passed to the server as normal input: "<<veredict<<".\n\n"<<std::endl;
  /* perform the attack into Ctr mode */
  std::cout<<"Main log | attacker path, with attack."<<std::endl;
  flag = attacker->attackCtrMode(&res);
  if (flag == false) {
    perror("\nThere was an error in the function 'Attacker::attackCtrMode'.");
  }
  veredict = (res == true) ? "true" : "false";
  std::cout<<"Main log | Attacker output: Admin search veredict after the 'Attacker::attackerCtrMode' function: "<<veredict<<"."<<std::endl;
  if (res == true) {
    std::cout<<"\nMain log | Test passed."<<std::endl;
  } else {
    std::cout<<"\nMain log | Test failed."<<std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
