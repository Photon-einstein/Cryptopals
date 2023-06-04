#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.h"

/* constructor / destructor */
Server::Server() {
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
void Server::setSeed() {
  _currentSeed = std::time(nullptr);
}
/******************************************************************************/
/* this function will run a simulation of the custom MT19937 and will perform
the seed, and afterwards it will return the first number of pseudo random
number generator */
unsigned int Server::returnFirst32BitsOfRNG() {
  /* simulation setup */
  /* first random delay */
  if (debugFlag == true) {
    std::cout<<"Server log | Initializing seed setup."<<std::endl;
  }
  int sleepTime = Server::getRandomDelay();
  std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::seconds(sleepTime));
  Server::setSeed();
  _mt19937_homeMade = std::make_shared<MT19937>(_currentSeed);
  /* second random delay */
  sleepTime = Server::getRandomDelay();
  std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::seconds(sleepTime));
  if (debugFlag == true) {
    std::cout<<"Server log | Finish seed setup."<<std::endl;
  }
  /* simulation */
  int i;
  unsigned int n;
  n = _mt19937_homeMade->extractNumber();
  if (debugFlag == true) {
    std::cout<<"Server log | Seed "<<_currentSeed<<"."<<std::endl;
  }
  return n;
}
/******************************************************************************/
/* this function will return a random delay between 1 and _maxDelay seconds, and
then it will return this value */
int Server::getRandomDelay() {
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(_minDelay,  _maxDelay); // distribute results between _minDelay and _maxDelay inclusive
  return dist(gen);
}
/******************************************************************************/
