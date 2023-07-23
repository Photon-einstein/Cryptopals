#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.h"
#include "./../include/Function.h"

/* constructor / destructor */
Server::Server() {
  Server::setSeed();
  Server::setRandomPrefixSize();
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
void Server::setSeed() {
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(0, INT_MAX); // distribute results between 0 and INT_MAX inclusive
  _currentSeed = dist(gen) & 0x0000ffff; // downsize the seed to 16 bits in this problem
  _mt19937_homeMadeEncrypt = std::make_shared<MT19937>(_currentSeed);
  _mt19937_homeMadeDecrypt = std::make_shared<MT19937>(_currentSeed);
  _numberLettersEncryptedWithSameSeed = 0;
  std::cout<<"Server log | seed mt19937: "<<_currentSeed<<".\n"<<std::endl;
  return;
}
/******************************************************************************/
void Server::setRandomPrefixSize() {
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(0, _maxRandomNumberLetters); // distribute results between 0 and maxRandonNumberLetters inclusive
  _randomPrefixSize = dist(gen);
}
/******************************************************************************/
/* this function will extract the next 32 bit number from the mt1997 PRNG and
it will convert that number into a keystream of 8 bit, return those 8 bits */
unsigned char Server::getNextKeyStream(std::shared_ptr<MT19937> &mt19937) {
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
/* this function will encrypt a given plaintext, made at the server, using a
stream cypher based on a MT19937 PRNG, in the end it will return the encrypted
data in a vector */
std::vector<unsigned char> Server::encryptWithStreamCypherBasedOnMt19937() {
  if (debugFlag == true) {
    std::cout<<"Encrypt"<<std::endl;
  }
  std::string plaintext = Server::getKnownPlaintext();
  printf("Plaintext: (server test):\t   \'");
  fflush(NULL);
  std::cout<<plaintext<<"\'"<<std::endl;
  unsigned char c;
  std::vector<unsigned char> v;
  int i, size = plaintext.size();
  if(_numberLettersEncryptedWithSameSeed+size > _maxCharactersMt19937WithSameSeed) {
    Server::setSeed();
    _numberLettersEncryptedWithSameSeed = 0;
  }
  _numberLettersEncryptedWithSameSeed+=size;
  for(i = 0; i < size; ++i) {
    c = Server::getNextKeyStream(_mt19937_homeMadeEncrypt);
    if (debugFlag == true) {
      printf("\nNext number (encrypt): %d", c);
    }
    v.emplace_back((unsigned char)plaintext[i]^c);
  }
  return v;
}
/******************************************************************************/
/* this function will encrypt a given plaintext using a stream cypher based on a
MT19937 PRNG, in the end it will return the encrypted data in a vector */
std::vector<unsigned char> Server::encryptWithStreamCypherBasedOnMt19937
    (std::string plaintext) {
  if (debugFlag == true) {
    std::cout<<"Encrypt"<<std::endl;
  }
  unsigned char c;
  std::vector<unsigned char> v;
  int i, size = plaintext.size();
  if(_numberLettersEncryptedWithSameSeed+size > _maxCharactersMt19937WithSameSeed) {
    Server::setSeed();
    _numberLettersEncryptedWithSameSeed = 0;
  }
  _numberLettersEncryptedWithSameSeed+=size;
  for(i = 0; i < size; ++i) {
    c = Server::getNextKeyStream(_mt19937_homeMadeEncrypt);
    if (debugFlag == true) {
      printf("\nNext number (encrypt): %d", c);
    }
    v.emplace_back((unsigned char)plaintext[i]^c);
  }
  return v;
}
/******************************************************************************/
/* this function will decrypt a given ciphertext that was created with a stream
cypher based on a MT19937 PRNG, in the end it will return a string with the
encrypted data in a vector */
std::string Server::decryptWithStreamCypherBasedOnMt19937(std::vector<unsigned char> ciphertextV) {
  if (debugFlag == true) {
    std::cout<<"Decrypt"<<std::endl;
  }
  std::vector<unsigned char> plaintextV;
  std::string plaintext;
  unsigned char c;
  int i, size = ciphertextV.size();
  if(_numberLettersEncryptedWithSameSeed+size > _maxCharactersMt19937WithSameSeed) {
    Server::setSeed();
    _numberLettersEncryptedWithSameSeed = 0;
  }
  _numberLettersEncryptedWithSameSeed+=size;
  for(i = 0; i < size; ++i) {
    c = Server::getNextKeyStream(_mt19937_homeMadeDecrypt);
    if (debugFlag == true) {
      printf("\nNext number (decrypt): %d", c);
    }
    plaintextV.emplace_back((unsigned char)ciphertextV[i]^c);
  }
  Function::convertVectorBytesToString(plaintextV, plaintext);
  return plaintext;
}
/******************************************************************************/
/* this function will return a string with a random number of random characters
as prefix followed by 14 A's */
std::string Server::getKnownPlaintext() {
  std::string s;
  unsigned char c;
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(0, UCHAR_MAX); // distribute results between 0 and UCHAR_MAX inclusive
  int i;
  // add prefix of random letters
  for (i = 0; i < _maxRandomNumberLetters; ++i) {
    s.push_back((unsigned char)dist(gen));
  }
  // add fixed number of A's
  for (i = 0; i < _numberOfAsLetters; ++i) {
    s.push_back('A');
  }
  return s;
}
/******************************************************************************/
/* this function will decide randonly if it will just generate a randon string
or else it will generate a password token that is the product of an MT19937 PRNG
seeded with a random seed up to 16 bits */
std::string Server::generatePossiblePasswordToken() {
  std::string s = "";
  std::random_device rd1;   // non-deterministic generator
  std::mt19937 gen1(rd1());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0, 1); // distribute results between 0 and 1 inclusive
  /* calculation of the size of the string */
  std::random_device rd2;   // non-deterministic generator
  std::mt19937 gen2(rd2());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist2(0, _maxRandomNumberLetters*5); // distribute results between 0 and 1 inclusive
  int sizeString = dist2(gen2);
  int i;
  idPossiblePasswordToken id;
  if (dist1(gen1) == 0) {
    /* create just a random string, without the use of the PRNG MT19937 */
    std::srand(std::time(nullptr)); // use current time as seed for random generator
    int random_variable = std::rand();
    unsigned char c;
    for (i = 0; i < sizeString; ++i) {
      c = std::rand()%(UCHAR_MAX+1);
      s.push_back(c);
    }
    /* update _mPasswordToken map */
    id.useMt19937Flag = false;
    _mPasswordToken.insert({s, id});
  } else {
    /* create a random string with the use of a PRNG MT19937, force a new seed */
    Server::setSeed();
    if(_numberLettersEncryptedWithSameSeed+sizeString > _maxCharactersMt19937WithSameSeed) {
      Server::setSeed();
      _numberLettersEncryptedWithSameSeed = 0;
    }
    _numberLettersEncryptedWithSameSeed+=sizeString;
    for (i = 0; i < sizeString; ++i) {
      s.push_back(Server::getNextKeyStream(_mt19937_homeMadeEncrypt));
    }
    /* update _mPasswordToken map */
    id.useMt19937Flag = true;
    id.seedMt19937 = _currentSeed;
    _mPasswordToken.insert({s, id});
  }
  return s;
}
/******************************************************************************/
/* this function will check if for a given password reset token, if the answer
given by the attacker were correct or not, if it were correct then it will return
true, false otherwise */
bool Server::checkAttackerAnswer(const std::string &passwordToken,
    const idPossiblePasswordToken &idAnswer) {
  bool veridictServer;
  /* case 1: the passwordToken that was passed to this function does not exists
  in the database */
  if (_mPasswordToken.count(passwordToken) == 0) {
    std::cout<<"Server log | password reset token "<<" is not present in the database."<<std::endl;
    return false;
  }
  // case 2: the veredict of the attacker does not match the server's database
  if (_mPasswordToken[passwordToken].useMt19937Flag != idAnswer.useMt19937Flag) {
    std::cout<<"Server log | password reset token "<<" false veredict."<<std::endl;
    return false;
  }
  /* case 3: the veredict of the attacker matches the server's database, no
  PRNG Mt19937 was used */
  if (_mPasswordToken[passwordToken].useMt19937Flag == false) {
    std::cout<<"Server log | password reset token "<<" true veredict | no PRNG MT19937 was used."<<std::endl;
    return true;
  }
  /* case 4: bool veredict was correct but seed used does not match database
  value */
  if (_mPasswordToken[passwordToken].seedMt19937 != idAnswer.seedMt19937) {
    std::cout<<"Server log | password reset token "<<" false veredict | PRNG MT19937's seed incorrectly guessed."<<std::endl;
    return true;
  } else {
  /* case 5: bool veredict and seed were correct, as both matches database
    values */
      std::cout<<"Server log | password reset token "<<" true veredict | PRNG MT19937's seed correctly guessed | seed = "
        <<idAnswer.seedMt19937<<"."<<std::endl;
      return true;
  }
}
/******************************************************************************/
