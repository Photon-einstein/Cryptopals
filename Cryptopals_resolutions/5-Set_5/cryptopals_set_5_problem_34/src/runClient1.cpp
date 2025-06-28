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
  const std::string clientId{"Bob"}, groupNameDH{"rfc3526-group-18"};
  std::shared_ptr<Client> client =
      std::make_shared<Client>(clientId, debugFlag, groupNameDH);
  const std::tuple<bool, std::string, std::string> keyExchangeResult =
      client->diffieHellmanKeyExchange(client->getProductionPort());
  if (std::get<0>(keyExchangeResult) == false) {
    throw std::runtime_error(
        "runClient1 log | diffieHellmanKeyExchange() failed.");
  }
  const std::string sessionId = std::get<2>(keyExchangeResult);
  client->messageExchange(client->getProductionPort(), sessionId);
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.\n", time);
  return 0;
}
/******************************************************************************/
