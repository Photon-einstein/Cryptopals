#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

#include "./../include/Client.hpp"
#include "./../include/MessageExtractionFacility.hpp"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  const bool debugFlag{false};
  const std::string clientId{"Eve"};
  std::shared_ptr<Client> client =
      std::make_shared<Client>(clientId, debugFlag);
  client->diffieHellmanKeyExchange();
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
