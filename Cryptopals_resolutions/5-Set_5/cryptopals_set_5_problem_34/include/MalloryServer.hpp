#ifndef MALLORY_SERVER_HPP
#define MALLORY_SERVER_HPP

#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <openssl/aes.h>
#include <vector>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"
#include "MallorySessionData.hpp"
#include "SessionData.hpp"

class MalloryServer {
public:
  /* constructor / destructor */
  explicit MalloryServer(const bool debugFlag, const bool testFlag);
  explicit MalloryServer(const bool debugFlag, const bool testFlag,
                         const bool parameterInjection);
  ~MalloryServer();

  /**
   * @brief This method will start all the server's endpoints in a multithread
   * environment.
   *
   * This method will start all the endpoints that the server provides to their
   * clients.
   */
  void runServer();

  /**
   * @brief This method will start all the server's endpoints in a multithread
   * environment for a test scenario.
   *
   * This method will start all the endpoints that the server provides to their
   * clients, in a test scenario.
   */
  void runServerTest();

  /**
   * @brief This method will clear all the sessions in memory.
   *
   * This method will clear all the sessions in memory that were created
   * after the conclusion of the Diffie Hellman key exchange protocol.
   */
  void clearDiffieHellmanSessionData();

  /**
   * @brief This method will return the server's production port.
   *
   * This method will return the server's production port to establish a
   * connection.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the server's test port.
   *
   * This method will return the server's test port to establish a
   * connection.
   */
  const int getTestPort() const;

  /**
   * @brief This method will set the value of the parameter injection flag.
   *
   * This method will set the value of the parameter injection flag, to decide
   * if a normal MITM attack is performed or one with a parameter injection
   * instead.
   */
  void setParameterInjectionFlag(const bool parameterInjectionFlag);

private:
  /* private methods */

  /**
   * @brief This method will start the endpoints that the server
   * provides to his clients.
   *
   * This method will start the endpoints that the server
   * provides to his clients, namely the root endpoint and the signature
   * verification endpoint.
   */
  void setupRoutes();

  /**
   * @brief This method is the entry point for the server URL address.
   *
   * This method will serve as a confirmation that the server URL is up
   * and running at the root path.
   */
  void rootEndpoint();

  /**
   * @brief This method runs the route that performs the Diffie Hellman
   * key exchange protocol. The man in the middle attack is performed.
   *
   * This method runs the route that performs the Diffie Hellman
   * key exchange protocol. It receives requests and make all the calculations
   * to respond to the requests, creating a symmetric key for each connection
   * request, performing the man in the middle attack.
   */
  void keyExchangeRoute();

  /**
   * @brief This method runs the route that performs the message exchange using
   * symmetric encryption after the Diffie Hellman key exchange protocol has
   * been completed. The man in the middle attack is performed.
   *
   * This method runs the route that performs the message exchange using
   * symmetric encryption after the Diffie Hellman key exchange protocol has
   * been completed. This fake server performs the man in the middle attack.
   * Normal function from a normal server is to receive messages from clients,
   * checks the validity of the session id and if valid, sends back a
   * confirmation response. This fake server decrypt, read and encrypt again
   * with another session to the real server.
   *
   * @throws std::runtime_error if there is an error in messageExchangeRoute.
   */
  void messageExchangeRoute();

  /**
   * @brief This method runs the route that gets all the current available
   * fake sessions created using the Diffie Hellman key exchange protocol, after
   * the man in the middle attack is performed.
   *
   * This method runs the route that gets all the current available sessions
   * created using the Diffie Hellman key exchange protocol, after
   * the man in the middle attack is performed.
   * It outputs all the session data in json format.
   */
  void getSessionsDataEndpoint();

  /**
   * @brief This method will generate an unique session's id.
   *
   * This method will generate an unique session's id for a given connection
   * request.
   *
   * @return An unique session's ID to be used.
   */
  boost::uuids::uuid generateUniqueSessionId();

  /* private fields */
  mutable std::mutex _diffieHellmanMapMutex;
  std::map<boost::uuids::uuid, std::unique_ptr<MallorySessionData>>
      _diffieHellmanMap;
  const std::size_t _nonceSize{16}; // bytes
  crow::SimpleApp _app;
  const int _portProduction{18080};
  const int _portTest{18081};
  const int _portRealServerProduction{18082};
  const int _portRealServerTest{18083};
  int _portRealServerInUse;
  std::thread _serverThread;
  const bool _debugFlag;
  const bool _testFlag;
  const std::size_t _ivLength{AES_BLOCK_SIZE}; // bytes
  std::string _serverId{"Mallory_Server_"};
  bool _parameterInjection{false};
};

#endif // MALLORY_SERVER_HPP
