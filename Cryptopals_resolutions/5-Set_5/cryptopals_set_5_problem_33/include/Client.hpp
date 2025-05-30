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
  struct SessionData {
    std::unique_ptr<MyCryptoLibrary::Diffie_Hellman> _diffieHellman;
    std::string _serverNonceHex;
    std::string _clientNonceHex;
    std::string _derivedKeyHex;
    SessionData(std::unique_ptr<MyCryptoLibrary::Diffie_Hellman> diffieHellman,
                const std::string &serverNonceHex,
                const std::string &clientNonceHex)
        : _diffieHellman(std::move(diffieHellman)),
          _serverNonceHex{serverNonceHex}, _clientNonceHex{clientNonceHex} {}
  };

  void printServerResponse(const cpr::Response &response);

  std::map<std::string, std::unique_ptr<SessionData>> _diffieHellmanMap;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId = "Bob";
  const std::size_t _nonceSize{16}; // bytes
  const bool _debugFlag;
};

#endif // CLIENT_HPP
