#include "crow.h"
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

#include "./../include/HMAC.hpp"
#include "./../include/HMAC_SHA1.hpp"
#include "./../include/Server.hpp"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  const bool debugFlag{true};
  std::shared_ptr<Server> server = std::make_shared<Server>(debugFlag);
  std::shared_ptr<MyCryptoLibrary::HMAC> hmac_sha1 =
      std::make_shared<MyCryptoLibrary::HMAC_SHA1>();
  // check attacker
  crow::SimpleApp app;

  // Root route
  CROW_ROUTE(app, "/")
  ([]() { return "Welcome to the Train Ticketing System!"; });

  // Route to list trains
  CROW_ROUTE(app, "/trains")([]() { return "List of all trains"; });

  // Route to get a train by number
  CROW_ROUTE(app, "/trains/<string>")
  ([](const std::string &trainNumber) {
    return "Details for train " + trainNumber;
  });

  // Route to purchase a ticket (POST)
  CROW_ROUTE(app, "/tickets/purchase")
      .methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        // You could parse JSON from req.body here
        return crow::response(201, "Ticket purchased!");
      });

  // Route to cancel a ticket
  CROW_ROUTE(app, "/tickets/cancel/<int>")
      .methods(crow::HTTPMethod::DELETE)([](int ticketId) {
        return "Ticket with ID " + std::to_string(ticketId) + " canceled";
      });

  app.port(18080).multithreaded().run();
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/