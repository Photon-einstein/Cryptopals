#include <stdexcept>

#include "./../include/Server.h"

/* constructor / destructor */
Server::Server(int numberTests, int numberSimulationsPerTest) {
  _numberTests = numberTests;
  _numberSimulationsPerTest = numberSimulationsPerTest;
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
void Server::setSeed() {
  _currentSeed = std::time(nullptr)+_entropy;
  ++_entropy;
}
/******************************************************************************/
/* this function will run a simulation of the custom and off the shelf
implementation of the MT19937_H, in the end it will return true if the
results were equal, or false if not, it will also returnby reference the
value of the seedUsed */
bool Server::runSimulation(std::time_t *seedUsed) {
  /* simulation setup */
  Server::setSeed();
  *seedUsed = _currentSeed;
  _mt19937_homeMade = std::make_shared<MT19937>(_currentSeed);
  _mt19937_offTheShelf.seed(_currentSeed);
  /* simulation */
  int i;
  unsigned int n1, n2;
  for (i = 0; i < _numberSimulationsPerTest; ++i) {
    n1 = _mt19937_homeMade->extractNumber();
    n2 = _mt19937_offTheShelf();
    if (debugFlag == true) {
      std::cout<<"Seed "<<_currentSeed<<" | simulation "<<i+1<<" | "<<
        " mt19937 homeMade "<<n1<<" | mt19937 offTheShelf "<<n2<<std::endl;
    }
    if (n1 != n2) {
      return false;
    }
  }
  return true;
}
/******************************************************************************/
/* this function will run the _numberTests tests and if all the tests pass
then it will return true, false otherwise */
bool Server::runTests() {
  int i;
  std::time_t seedUsed;
  bool b;
  for (i = 0; i < _numberTests; ++i) {
    b = Server::runSimulation(&seedUsed);
    if (b == false) {
      std::cout<<"There was a failed simulation at the test with the seed "<<seedUsed<<"."<<std::endl;
      return false;
    }
    std::cout<<"Test "<<i+1<<" passed"<<" | seed "<<seedUsed<<std::endl;
  }
  return true;
}
/******************************************************************************/
