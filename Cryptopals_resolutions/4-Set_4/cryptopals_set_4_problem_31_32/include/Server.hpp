#ifndef SERVER_HPP
#define SERVER_HPP

#include "crow.h"
#include <vector>

#include "./../include/HMAC.hpp"
#include "./../include/HMAC_SHA1.hpp"

class Server {
public:
  /* constructor / destructor */
  Server();
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

  /**
   * @brief This method is the endpoint that makes the verification of the
   * signature
   *
   * This method is the endpoint that makes the verification of the signature,
   * namely it assesses if HMAC(file) == signature
   *
   */
  void signatureVerificationEndpoint();

  /**
   * @brief This method will do an insecure compare between two vector.
   *
   * This method will do an insecure compare between two vector, leaking time
   * in the process.
   *
   * @return A bool value, true if the vectors are the same, false otherwise
   */
  static bool insecureSignatureCompare(const std::vector<unsigned char> &v1,
                                       const std::vector<unsigned char> &v2);

  std::vector<unsigned char> _keyServer{};
  crow::SimpleApp _app;
  std::shared_ptr<MyCryptoLibrary::HMAC> _hmac;

  const int _portProduction{18080};
  const int _portTest{18081};

  std::thread _serverThread;
};

#endif // SERVER_HPP
