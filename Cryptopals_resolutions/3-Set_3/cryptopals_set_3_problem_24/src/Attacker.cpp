#include <stdexcept>
#include <chrono>
#include <cmath>

#include "./../include/Server.h"
#include "./../include/Attacker.h"
#include "./../include/Function.h"

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
/* this function will extract the next 32 bit number from the mt1997 PRNG and
it will convert that number into a keystream of 8 bit, return those 8 bits */
unsigned char Attacker::getNextKeyStream(std::shared_ptr<MT19937> &mt19937) {
  unsigned int n = mt19937->extractNumber();
  unsigned char *pNumber = (unsigned char*)&n;
  unsigned char res=0;
  int i;
  const int numberBytesInInteger = 4;
  for (i = 0; i < numberBytesInInteger; ++i, ++pNumber) {
    res^=*pNumber;
  }
  return res;
}
/******************************************************************************/
/* this function will extract the next 32 bit number from the mt1997 PRNG and
it will convert that number into a keystream of 8 bit, return those 8 bits */
unsigned char Attacker::getNextKeyStream(MT19937 &mt19937) {
  unsigned int n = mt19937.extractNumber();
  unsigned char *pNumber = (unsigned char*)&n;
  unsigned char res=0;
  int i;
  const int numberBytesInInteger = 4;
  for (i = 0; i < numberBytesInInteger; ++i, ++pNumber) {
    res^=*pNumber;
  }
  return res;
}
/******************************************************************************/
/* this function will recover the key by reference used by the server in the
mt19937 stream cipher, having as input the vector ciphertext, returning true if
all went ok or false otherwise */
bool Attacker::recoverTheKey(const std::vector<unsigned char> &ciphertext,
    unsigned int &seed) {
  if (ciphertext.size() < _lengthStringsA) {
    return false;
  }
  seed=0;
  bool found = false;
  int i, j, size = ciphertext.size();
  unsigned char c;
  while(found == false && seed < _maxSeed) {
    MT19937 mt19937Attacker(seed);
    /* test maxLengthTry times */
    j = 0;
    while(j+size <= _maxLengthTry) {
      for(i = 0, found = true; i < size; ++i) {
        c = (unsigned char)Attacker::getNextKeyStream(mt19937Attacker) ^ ciphertext[i];
        if (i >= size- _lengthStringsA && i <= size-1 && c != 'A') {
          found = false;
        }
      } // for
      if (found == true) {
        break;
      }
      j+=size;
    } // while
    if (found == true) {
      break;
    }
    /* advance the seed to the next value */
    ++seed;
  } // while
  /* return output value */
  return found;
}
/******************************************************************************/
/* this function will recover the key by reference used by the server in the
mt19937 stream cipher, asking first to the server for a given ciphertext
that the attacker knows before hand that it will end in 14 A's,
this function has as input the vector ciphertext, returning true if all went ok
or false otherwise */
bool Attacker::recoverTheKeyFromTheServer(unsigned int &seed) {
  std::vector<unsigned char> ciphertext = _server->encryptWithStreamCypherBasedOnMt19937
      (_server->getKnownPlaintext());
  bool b = Attacker::recoverTheKey(ciphertext, seed);
  if (b == false) {
    perror("There was a problem in the function 'Attacker::recoverTheKey'.");
    return b;
  }
  std::cout<<"\nAttacker log | seed cracked mt19937 from server: "<<seed<<".\n"<<std::endl;
  return b;
}
/******************************************************************************/
/* this function will perform _Tests amounnt of tests agains the server's
database, and if it passes all it will return true, false otherwise */
bool Attacker::performTestsAgainstServer() {
  int i;
  bool b;
  std::string possiblePasswordResetToken;
  idPossiblePasswordToken idAnswer;
  for (i = 0; i < _nTests; ++i) {
    possiblePasswordResetToken.clear();
    possiblePasswordResetToken = _server->generatePossiblePasswordToken();
    idAnswer = Attacker::calculatePossiblePasswordResetTokenVeredict(possiblePasswordResetToken);
    b = _server->checkAttackerAnswer(possiblePasswordResetToken, idAnswer);
    if (b == true) {
      std::cout<<"Attacker log | Password reset token attack test number "<<i+1<<
        " passed.\n"<<std::endl;
    } else {
      std::cout<<"Attacker log | Password reset token attack test number "<<i+1<<
        " failed.\n"<<std::endl;
      return false;
    }
  }
  // if it reaches here then it has passed all the tests
  std::cout<<"Attacker log | All tests passed regarding Password reset token."<<std::endl;
  return true;
}
/******************************************************************************/
/* this function will make the server's attack agains the password reset token,
trying to decide if the string possiblePasswordResetToken was the product of a
PRNG MT19937 or not, and if yes, what was the seed that was used, returning that
information at the structure idPossiblePasswordToken */
idPossiblePasswordToken Attacker::calculatePossiblePasswordResetTokenVeredict
    (const std::string &possiblePasswordResetToken) {
  idPossiblePasswordToken idAnswer;
  int size = possiblePasswordResetToken.size();
  const unsigned int maxSeed = USHRT_MAX & 0x0000ffff; // maxSeed truncated to 16 bits
  unsigned int seed, i;
  std::string sTest;
  idPossiblePasswordToken idAttacker;
  /* fill out default configuration into idAttacker */
  idAttacker.useMt19937Flag = false;
  idAttacker.seedMt19937 = 0;
  // carry out the test regarding all the seeds up to 16 bits inclusive
  for (seed = 0; seed <= maxSeed; ++seed) {
    _mt19937Attacker = std::make_shared<MT19937>(seed);
    sTest.clear();
    // load characters into the string
    for(i = 0; i < _maxLengthTry; ++i) {
      sTest.push_back(Attacker::getNextKeyStream(_mt19937Attacker));
    }
    // test substrings
    for (i = 0; i + size < _maxLengthTry; ++i) {
      if (sTest.substr(i, size) == possiblePasswordResetToken) {
        /* we have found a match, possiblePasswordResetToken is a product of
        MT19937 PRNG, with a seed of seed value */
        idAttacker.useMt19937Flag = true;
        idAttacker.seedMt19937 = seed;
        return idAttacker;
      }
    }
  }
  /* if it reaches here then we have not found a valid seed to have the same
  possiblePasswordResetToken */
  return idAnswer;
}
/******************************************************************************/
