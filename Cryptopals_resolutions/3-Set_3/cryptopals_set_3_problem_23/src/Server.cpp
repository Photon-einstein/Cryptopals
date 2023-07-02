#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.h"

/* constructor / destructor */
Server::Server() {
  Server::setSeed();
  _mt19937_homeMade = std::make_shared<MT19937>(_currentSeed);
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
void Server::setSeed() {
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(0, INT_MAX); // distribute results between 0 and LONG_MAX inclusive
  _currentSeed = dist(gen);
  std::cout<<"Server log | seed mt19937: "<<_currentSeed<<".\n"<<std::endl;
  return;
}
/******************************************************************************/
/* this function will call the _mt19937_homeMade and will extract the next
number from the PRNG */
unsigned int Server::extractNumberFromMt19937HomeMade() {
  return _mt19937_homeMade->extractNumber();
}
/******************************************************************************/
/* this function will return true if the vector _mt19937StateVector has the
same value as the internal state of MT19937 or false otherwise */
bool Server::checkEqualVectorStateAtServer(const std::vector<std::uint32_t> &_mt19937StateVector) {
  return _mt19937_homeMade->checkEqualVectorState(_mt19937StateVector);
}
/******************************************************************************/
