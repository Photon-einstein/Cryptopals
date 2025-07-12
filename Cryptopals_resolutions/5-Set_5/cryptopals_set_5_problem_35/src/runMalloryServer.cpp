#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

#include "./../include/MalloryServer.hpp"
#include "./../include/MessageExtractionFacility.hpp"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  const bool debugFlag{false}, testFlag{false}, parameterInjection{false};
  std::shared_ptr<MalloryServer> server =
      std::make_shared<MalloryServer>(debugFlag, testFlag, parameterInjection);
  server->runServer();
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.\n", time);
  return 0;
}
/******************************************************************************/