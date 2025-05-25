#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "Diffie_Hellman.hpp"

class Client {
public:
  /* constructor / destructor*/
  Client();
  ~Client();

private:
  std::shared_ptr<MyCryptoLibrary::Diffie_Hellman> _diffieHellman;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};
};

#endif // CLIENT_HPP
