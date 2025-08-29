#ifndef SERVER_HPP
#define SERVER_HPP

#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <openssl/aes.h>
#include <vector>

#include "EncryptionUtility.hpp"
#include "SessionData.hpp"
#include "SrpParametersLoader.hpp"

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
   * @param defaultGroupId The default group id is the minimum pre-requisite
   * regarding the security definitions of the Secure Remote Password protocol.
   *
   */
  explicit Server(const bool debugFlag, const unsigned int defaultGroupId = 3);

  /**
   * @brief This method will perform the destruction of the Server object.
   *
   * This method will perform the destruction of the Server object, releasing
   * all the resources and memory used.
   */
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

  /**
   * @brief This method will return the production port of the server.
   *
   * This method will return the production port of the server to establish a
   * connection.
   *
   * @return The production port of the server.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the test port of the server.
   *
   * This method will return the test port of the server to establish a
   * connection.
   *
   * @return The test port of the server.
   */
  const int getTestPort() const;

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Secure Remote Password protocol are available.
   *
   * @return Filename where the public configurations of the Secure Remote
   * Password protocol are available.
   */
  const std::string &getSrpParametersFilenameLocation();

  /**
   * @brief This method returns the default group ID of SRP public parameters.
   * This value is used when the user does not provide a group ID during the
   * Secure remote password protocol.
   *
   * @return The default group ID of SRP public parameters.
   */
  const int getDefaultGroupId();

private:
  /* private methods */

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
   * @brief This method runs the route that performs group search inside the
   * registration step.
   *
   * This method runs the route that performs group search inside the
   * registration step, returning the agreed group id and the salt.
   */
  void getGroupsData();

  /**
   * @brief This method runs the route that performs the Secure Remote Password
   * protocol authentication.
   *
   * This method runs the route that performs the Secure Remote Password
   * protocol. It receives requests and make all the calculations to response to
   * the requests, creating a symmetric key for each connection request, after
   * performing the authentication.
   */
  void authenticationRoute();

  /* private fields */
  crow::SimpleApp _app;

  mutable std::mutex _secureRemotePasswordMapMutex;
  std::map<std::string, std::unique_ptr<SessionData>> _secureRemotePasswordMap;

  const int _portProduction{18080};
  const int _portTest{18081};

  std::thread _serverThread;
  const bool _debugFlag;

  const std::string _srpParametersFilename{"../input/SrpParameters.json"};
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _defaultGroupId;
  unsigned int _minGroupId, _maxGroupId;

  const std::map<std::string, unsigned int> _minSaltSizesMap;
};

#endif // SERVER_HPP
