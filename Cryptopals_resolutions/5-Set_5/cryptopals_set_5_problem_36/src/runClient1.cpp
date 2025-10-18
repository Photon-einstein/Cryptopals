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
  const std::string clientId{"Bob"};
  const unsigned int requestedGroup{5};
  std::shared_ptr<Client> client{std::make_shared<Client>(clientId, debugFlag)};
  const bool registrationResult{
      client->registration(client->getProductionPort(), requestedGroup)};
  if (registrationResult == false) {
    throw std::runtime_error("runClient1 log | registration() failed.");
  }
  std::cout << "\nClient " << clientId
            << "'s registration was completed with success.\n"
            << std::endl;
  const bool authenticationResult{
      client->authentication(client->getProductionPort())};
  if (authenticationResult == false) {
    throw std::runtime_error("runClient1 log | authentication() failed.");
  }
  std::cout << "Client " << clientId
            << "'s authentication was completed with success." << std::endl;
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
