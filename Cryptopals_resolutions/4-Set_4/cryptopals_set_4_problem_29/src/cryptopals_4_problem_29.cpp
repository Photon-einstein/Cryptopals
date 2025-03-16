#include <iostream>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

#include "./../include/Attacker.hpp"
#include "./../include/MessageFormat.hpp"
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
  std::string message = attacker->extractMessage(attacker->messageLocation);
  MessageFormat::MessageParsed msgParsed = attacker->parseMessage(message);
  attacker->computeSHA1padding(msgParsed.msg);
  attacker->tamperMessageTry(msgParsed);
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/