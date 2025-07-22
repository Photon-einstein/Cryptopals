#ifndef SERVER_HPP
#define SERVER_HPP

#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <openssl/aes.h>
#include <vector>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "EncryptionUtility.hpp"
#include "SessionData.hpp"

class Server {
public:
  /* constructor / destructor */

  /**
   * @brief This method will execute the constructor of the Server object.
   *
   * This method will execute the constructor of the Server object. It
   * needs to have as input the debugFlag.
   *
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   *
   */
  explicit Server(const bool debugFlag);

  /**
   * @brief This method will perform the destruction of the Server object.
   *
   * This method will perform the destruction of the Server object, releasing
   * all the resources and memory used.
   */
  ~Server();

  /**
   * @brief This method will start all the server's endpoint in a multi thread
   * environment.
   *
   * This method will start all the endpoints that the server provides to their
   * clients.
   */
  void runServer();

  /**
   * @brief This method will start all the server's endpoints in a multi thread
   * environment for a test scenario.
   *
   * This method will start all the endpoints that the server provides to their
   * clients, for a given test.
   */
  void runServerTest();

  /**
   * @brief This method will clear all the sessions in memory.
   *
   * This method will clear all the sessions in memory that were created
   * after the execution of the Diffie Hellman key exchange protocol.
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
   * @brief This method will return the Diffie Hellman's map.
   *
   * This method will return the Diffie Hellman's map of the client.
   *
   * @return The client's DH map.
   */
  std::map<boost::uuids::uuid, std::unique_ptr<SessionData>> &
  getDiffieHellmanMap();

private:
  /* private methods */

  /**
   * @brief This method will start the endpoints that the server
   * provides to his clients.
   *
   * This method will start the endpoints that the server
   * provides to his clients.
   */
  void setupRoutes();

  /**
   * @brief This method is the entry point for the server URL address
   *
   * This method will serve as a confirmation that the server's URL is up
   * and running at the root path.
   */
  void rootEndpoint();

  /**
   * @brief This method runs the route that performs the Diffie Hellman's
   * key exchange protocol.
   *
   * This method runs the route that performs the Diffie Hellman's
   * key exchange protocol. It receives requests and makes all the calculations
   * to respond to the requests, creating a symmetric key for each connection
   * request.
   *
   * @throws std::runtime_error if there was an error in the keyExchangeRoute.
   */
  void keyExchangeRoute();

  /**
   * @brief This method runs the route that performs the message exchange using
   * symmetric encryption after the Diffie Hellman's key exchange protocol has
   * been completed.
   *
   * This method runs the route that performs the message exchange using
   * symmetric encryption after the Diffie Hellman's key exchange protocol has
   * been completed. It receives messages from clients, checks the validity of
   * the session id and if valid, sends back a confirmation response.
   *
   * @throws std::runtime_error if there is an error in MessageExchangeRoute.
   */
  void messageExchangeRoute();

  /**
   * @brief This method runs the route that gets all the current available
   * sessions created using the Diffie Hellman's key exchange protocol.
   *
   * This method runs the route that gets all the current available sessions
   * created using the Diffie Hellman's key exchange protocol. It outputs all
   * the session data in json format.
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
  std::map<boost::uuids::uuid, std::unique_ptr<SessionData>> _diffieHellmanMap;
  const std::size_t _nonceSize{16}; // bytes
  crow::SimpleApp _app;
  const int _portProduction{18082};
  const int _portTest{18083};
  std::thread _serverThread;
  const bool _debugFlag;
  const std::size_t _ivLength{AES_BLOCK_SIZE}; // bytes
  std::string _serverId{"Server-Company_XYX_"};
};

#endif // SERVER_HPP
