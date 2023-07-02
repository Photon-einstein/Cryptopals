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
#include "./../include/MT19937.h"
#include "./../include/Attacker.h"

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  bool b;
  std::shared_ptr<Server> server = std::make_shared<Server>();
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(server);
  b = attacker->cloneMt19937();
  if (b == false) {
    std::cout<<"Test failed to clone the PRNG MT19937."<<std::endl;
  } else {
    std::cout<<"Test passed cloning the PRNG MT19937."<<std::endl;
  }
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
