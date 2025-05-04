#ifndef SERVER_HPP
#define SERVER_HPP

#include "crow.h"
#include <vector>

#include "./../include/HMAC.hpp"
#include "./../include/HMAC_SHA1.hpp"

class Server {
public:
  /* constructor / destructor */
  explicit Server(const bool debugFlag);
  ~Server();

  /**
   * @brief This method will validate if a given message produces the
   * given message authentication code (MAC)
   *
   * This method will validate if a given message produces the
   * given message authentication code (MAC), it will perform the following
   * test: MD4(private server key || msg) == mac
   *
   * @param msg The message to be authenticated
   * @param mac The message authentication code (mac) to be validated in
   * binary format
   *
   * @return A bool value, true if the mac received matches the
   * mac produced by the server, false otherwise
   */
  bool validateMac(const std::vector<unsigned char> &msg,
                   const std::vector<unsigned char> &mac);

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
  const bool _debugFlag;
  bool _debugFlagExtreme{false};
  std::vector<unsigned char> _keyServer{};
  crow::SimpleApp _app;
  std::shared_ptr<MyCryptoLibrary::HMAC> _hmac;

  mutable std::mutex _mutex;

  const int _portProduction{18080};
  const int _portTest{18081};
};

#endif // SERVER_HPP
