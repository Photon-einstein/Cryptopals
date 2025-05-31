#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "MessageExtractionFacility.hpp"

class Client {
public:
  /* constructor / destructor*/
  Client(const bool debugFlag);
  ~Client();

  /* public methods */

  /**
   * @brief This method will perform the Diffie Hellman key exchange protocol
   * with a given server.
   *
   * This method will perform the Diffie Hellman key exchange protocol with
   * a given server, in order to agree on a given symmetric encryption key.
   */
  void diffieHellmanKeyExchange();

private:
  /* private structures */
  struct SessionData {
    std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellman;
    std::string _serverNonceHex;
    std::string _clientNonceHex;
    std::string _derivedKeyHex;

    SessionData(std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman,
                const std::string &serverNonceHex,
                const std::string &clientNonceHex)
        : _diffieHellman(std::move(diffieHellman)),
          _serverNonceHex{serverNonceHex}, _clientNonceHex{clientNonceHex} {}
  };

  /* private methods */

  /**
   * @brief This method will print the server response to the Diffie Hellman
   * key exchange protocol.
   *
   * This method will print the server response to the Diffie Hellman
   * key exchange protocol. The response is a json text, and it will be printed
   * in a structured way.
   *
   * @param response The response received by the server during the execution
   * of the Diffie Hellman key exchange protocol.
   */
  void printServerResponse(const cpr::Response &response);

  /* private fields */

  std::map<std::string, std::unique_ptr<SessionData>> _diffieHellmanMap;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId = "Bob";
  const std::size_t _nonceSize{16}; // bytes
  const bool _debugFlag;
};

#endif // CLIENT_HPP
