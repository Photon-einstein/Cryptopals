#ifndef SERVER_HPP
#define SERVER_HPP

#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <vector>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"

class Server {
public:
  /* constructor / destructor */
  Server(const bool debugFlag);
  ~Server();

  /**
   * @brief This method will start all the server endpoints in a multi thread
   * environment
   *
   * This method will start all the endpoints that the server provides to their
   * clients
   */
  void runServer();

  /**
   * @brief This method will start all the server endpoints in a multi thread
   * environment for a test scenario
   *
   * This method will start all the endpoints that the server provides to their
   * clients, for a given test
   */
  void runServerTest();

private:
  struct SessionData {
    std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellman;
    std::string _serverNonceHex;
    std::string _clientNonceHex;
    std::string _derivedKeyHex;
    std::string _clientId;
    SessionData(const std::size_t nonceSize, const std::string &clientNonceHex,
                const std::string &clientId, const bool debugFlag)
        : _diffieHellman(
              std::make_unique<MyCryptoLibrary::DiffieHellman>(debugFlag)),
          _serverNonceHex(
              MessageExtractionFacility::generateCryptographicNonce(nonceSize)),
          _clientNonceHex{clientNonceHex}, _clientId{clientId} {}
  };

  /**
   * @brief This method will start the endpoints that the server
   * provides to his clients
   *
   * This method will start the endpoints that the server
   * provides to his clients, namely the root endpoint and the signature
   * verification endpoint
   */
  void setupRoutes();

  /**
   * @brief This method is the entry point for the server URL address
   *
   * This method will serve as a confirmation that the server URL is up
   * and running at the root path
   */
  void rootEndpoint();

  void keyExchangeRoute();

  boost::uuids::uuid generateUniqueSessionId();

  std::map<boost::uuids::uuid, std::unique_ptr<SessionData>> _diffieHellmanMap;
  const std::size_t _nonceSize{16}; // bytes

  crow::SimpleApp _app;

  const int _portProduction{18080};
  const int _portTest{18081};

  std::thread _serverThread;
  const bool _debugFlag;
};

#endif // SERVER_HPP
