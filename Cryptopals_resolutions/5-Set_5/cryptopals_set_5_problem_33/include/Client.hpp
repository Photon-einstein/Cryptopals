#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "DH_parameters_loader.hpp"
#include "Diffie_Hellman.hpp"
#include "MessageExtractionFacility.hpp"

class Client {
public:
  /* constructor / destructor*/
  Client();
  ~Client();

private:
  std::shared_ptr<MyCryptoLibrary::Diffie_Hellman> _diffieHellman;

  MessageExtractionFacility::UniqueBIGNUM _p, _g;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};
};

#endif // CLIENT_HPP
