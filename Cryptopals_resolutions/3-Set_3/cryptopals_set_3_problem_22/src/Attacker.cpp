#include <chrono>
#include <stdexcept>

#include "./../include/Attacker.h"
#include "./../include/Server.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server> &server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server> &server) { _server = server; }
/******************************************************************************/
/* this function will try to crack the seed of the MT19937 rng
if it can it will return true and the seedCracked by reference, false
otherwise */
bool Attacker::crackMt19937(std::time_t &seedCracked) {
  unsigned int firstNumber = _server->returnFirst32BitsOfRNG();
  auto now = std::chrono::system_clock::now();
  std::time_t timeNow = std::chrono::system_clock::to_time_t(now) + 1;
  while (timeNow >= 0) {
    std::shared_ptr<MT19937> mt19937_homeMade =
        std::make_shared<MT19937>(timeNow);
    if (firstNumber == mt19937_homeMade->extractNumber()) {
      seedCracked = timeNow;
      return true;
    }
    --timeNow;
  }
  return false;
}
/******************************************************************************/
