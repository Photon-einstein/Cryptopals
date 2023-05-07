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
#include "./../include/Attacker.h"

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string input, possibleSessionTokenObtained;
  bool flag, res;
  std::string resS, plaintext;
  std::shared_ptr<Pad> pad = std::make_shared<PadPKCS_7>(blockSize);
  std::shared_ptr<Server> server = std::make_shared<Server>("input/serverInput.txt", pad);
  std::vector<unsigned char> ciphertextV, ivV, plaintextV;
  std::shared_ptr<Attacker> attacker = std::make_shared<Attacker>(server, blockSize);
  flag = server->encryptionSessionTokenAesCbcMode(ciphertextV, ivV);
  if (flag == false) {
    perror("There was an error in the function 'encryptionSessionTokenAesCbcMode'.");
    return false;
  }
  flag = server->decryptAndCheckPaddingInSessionTokenAesCbcMode(ciphertextV, &res);
  if (flag == false) {
    perror("There was an error in the function 'decryptAndCheckPaddingInSessionTokenAesCbcMode'.");
    return false;
  }
  resS = (res == true) ? "true" : "false";
  std::cout<<"Server veredict on the padding of the ciphertext: "<<resS<<"."<<std::endl;
  /* test attacker */
  flag = attacker->attackCbcBlockCypherMode(possibleSessionTokenObtained, &res);
  if (flag == false) {
    perror("There was an error in the function 'attackCbcBlockCypherMode'.");
    return false;
  }
  res = server->checkPresenceOfValidSessionToken(possibleSessionTokenObtained);
  resS = (res == true) ? "true" : "false";
  std::cout<<"\n\n\n\n####  Server veredict on the presence of this token in the server: \""<<possibleSessionTokenObtained<<"\" -> "<<resS<<"."<<std::endl;
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
