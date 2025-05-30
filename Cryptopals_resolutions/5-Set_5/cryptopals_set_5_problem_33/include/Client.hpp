#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "DH_parameters_loader.hpp"
#include "Diffie_Hellman.hpp"
#include "MessageExtractionFacility.hpp"

class Client {
public:
  /* constructor / destructor*/
  Client(const bool debugFlag);
  ~Client();

  void diffieHellmanKeyExchange();

private:
  void printServerResponse(const cpr::Response &response);

  std::shared_ptr<MyCryptoLibrary::Diffie_Hellman> _diffieHellman;
  MessageExtractionFacility::UniqueBIGNUM _p, _g;
  std::string _sessionId;
  std::string _extractedNonceServer;
  std::string _derivedKeyHex;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId = "Bob";
  const std::size_t _nonceSize{16}; // bytes
  std::string _clientNonceHex;
  const bool _debugFlag;
};

#endif // CLIENT_HPP
