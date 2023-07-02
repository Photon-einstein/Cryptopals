#include <stdexcept>
#include <chrono>

#include "./../include/Server.h"
#include "./../include/Attacker.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server>& server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server>& server) {
  _server = server;
}
/******************************************************************************/
/* this function will ask for the first _internalStateValueSize values, so
that the attacker can then recover the full state of the MT19937 PRNG, in the
end the function will only return */
void Attacker::extractNumbersFromMt19937HomeMadeBeforeAttack() {
  int i;
  unsigned int n;
  for (i = 0; i < _internalStateValueSize; ++i) {
    n = _server->extractNumberFromMt19937HomeMade();
    _mt19937Values.push_back(n);
    if (debugFlag == true && i < maxSizeDebug) {
      std::cout<<"(sample) Attacker log read from server | _mt19937Values["<<i<<"] = "<<_mt19937Values[i]<<std::endl;
    }
  }
  std::cout<<"\nAttacker log | "<<_internalStateValueSize<<" values read.\n"<<std::endl;
  return;
}
/******************************************************************************/
/* this function will reverse this kind of operation:
Value = ValueBegin XOR ((ValueBegin >> shift)), in the end it will return the
value of the ValueBegin, starting with the value of value and shift */
std::uint32_t Attacker::reverseShiftRightXor(std::uint32_t value, std::uint8_t shift) {
  // iterate until we've done the full 32 bits
  for (size_t i = 0; i * shift < 32; ++i) {
    // create a mask for this part
    uint32_t partMask = (0xFFFFFFFF << (32 - shift)) >> (shift * i);
    // obtain the part
    uint32_t part = value & partMask;
    // unapply the xor from the next part of the integer
    value ^= part >> shift;
  }
  return value;
}
/******************************************************************************/
/* this function will reverse this kind of operation:
Value = ValueBegin XOR ((ValueBegin << shift) & mask), in the end it will return
the value of the ValueBegin, starting with the value of value, shift and the
mask */
std::uint32_t Attacker::reverseShiftLeftXor(std::uint32_t value, std::uint8_t shift,
    std::uint32_t mask) {
  // iterate until we've done the full 32 bits
  for (size_t i = 0; i * shift < 32; ++i) {
    // create a mask for this part
    uint32_t partMask = (0xFFFFFFFF >> (32 - shift)) << (shift * i);
    // obtain the part
    uint32_t part = value & partMask;
    // unapply the xor from the next part of the integer
    value ^= part << shift & mask;
  }
  return value;
}
/******************************************************************************/
/* this function will recover the complete state of the MT19937 using as input
the first 624 numbers extracted from the PRNG MT19937, in the end it will
return true if all went ok or false otherwise */
bool Attacker::recoverStateMt19937() {
  if (_mt19937Values.size() != _internalStateValueSize) {
    return false;
  }
  int i;
  std::uint32_t value;
  for (i = 0; i < _internalStateValueSize; ++i) {
    value = _mt19937Values[i];
    value = Attacker::reverseShiftRightXor(value, _l);
    value = Attacker::reverseShiftLeftXor(value, _t, _c);
    value = Attacker::reverseShiftLeftXor(value, _s, _b);
    value = Attacker::reverseShiftRightXor(value, _u);
    if (debugFlag == true && i < maxSizeDebug) {
      std::cout<<"(sample) attacker log mt19937 state vector | _mt_attacker["<<i<<"] = "<<value<<std::endl;
    }
    _mt19937StateVector.push_back(value);
  }
  if (debugFlag == true) {
    std::cout<<std::endl;
  }
  return true;
}
/******************************************************************************/
/* this function will test if the full state recovered in the function
'Attacker::recoverStateMt19937()' is correct, if yes it will return true, false
otherwise */
bool Attacker::testRecoverStateMt19937() {
  std::uint32_t nTest, nServer;
  int i;
  _mt19937Test = std::make_shared<MT19937>(10);
  // upload brand new mt vector */
  _mt19937Test->seedMt(_mt19937StateVector);
  if (_server->checkEqualVectorStateAtServer(_mt19937StateVector) == true) {
    std::cout<<"Clone state vector succeed.\n"<<std::endl;
  } else {
    std::cout<<"Clone state vector failed.\n"<<std::endl;
  }
  for (i = 0; i < _internalStateValueSize; ++i) {
    /* run the next 624 numbers to check if the mt19937 was cloned */
    nTest = _mt19937Test->extractNumber();
    nServer = _server->extractNumberFromMt19937HomeMade();
    if (nTest != nServer) {
      std::cout<<"Attacker log test | mt19937_atck["<<i<<"] = "<<nTest<<" != mt19937_srv["<<i<<"] = "<<nServer<<" | failed."<<std::endl;
      return false;
    } else if (debugFlag == true && i < maxSizeDebug) {
      std::cout<<"(sample new values) Attacker log test | mt19937_attacker["
        <<i<<"] = "<<nTest<<" | equals new server value | passed."<<std::endl;
    }
  }
  if (debugFlag == true) {
    std::cout<<std::endl;
  }
  return true;
};
/******************************************************************************/
/* this function will try to clone the PRNG MT19937, if it succeeds it will
return true, false otherwise */
bool Attacker::cloneMt19937() {
  bool b;
  Attacker::extractNumbersFromMt19937HomeMadeBeforeAttack();
  b = Attacker::recoverStateMt19937();
  if (b == false) {
    std::cout<<"There was an error in the function Attacker::cloneMt19937.";
    return false;
  }
  b = Attacker::testRecoverStateMt19937();
  if (b == false) {
    std::cout<<"There was an error in the function Attacker::testRecoverStateMt19937.";
    return false;
  }
  return true;
}
/******************************************************************************/
