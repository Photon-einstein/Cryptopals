#include <iostream>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

#include "./../include/Attacker.hpp"
#include "./../include/SHA1.hpp"
#include "./../include/Server.hpp"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  const bool debugFlag{true};
  std::shared_ptr<Server> server = std::make_shared<Server>(debugFlag);
  const bool writeToFile{true};
  std::shared_ptr<Attacker> attacker =
      std::make_shared<Attacker>(server, writeToFile);
  // check attacker
  const std::string messageLocation{"./../input/transaction_Alice_to_Bob.json"};
  attacker->tamperMessageTry(messageLocation);
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
