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

#include "./../include/Server.hpp"
#include "./../include/SHA1.hpp"

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::shared_ptr<Server> server = std::make_shared<Server>();
  const int sizePlaintext = 100;
  bool randomPlaintext {false};
  std::string plaintext = "Aasffefefdecfdsfcawwwd33432";
  std::vector<unsigned char> hashOpenSSL;
  std::vector<unsigned char> hash;
  server->setPlaintext(sizePlaintext, randomPlaintext, plaintext);
  hashOpenSSL = server->hashSHA1WithLibrary(server->getPlaintextV(), server->getPlaintext());
  hash = server->hashSHA1(server->getPlaintextV(), server->getPlaintext());
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
