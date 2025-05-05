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
  server->runServer();
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/