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
  CROW_ROUTE(app, "/") ([](){
      return "Hello, World!";
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