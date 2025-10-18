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
   * @param debugFlag The boolean flag decides if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param defaultGroupId The default group ID is the minimum pre-requisite
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
   * @brief This method will clear all the sessions in memory.
   *
   * This method will clear all the sessions in memory that were created
   * after the execution of the Secure Remote Password protocol.
   */
  void clearSecureRemotePasswordMap();

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
  const std::string &getSrpParametersFilenameLocation() const;

  /**
   * @brief This method returns the default group ID of SRP public parameters.
   * This value is used when the user does not provide a group ID during the
   * Secure remote password protocol.
   *
   * @return The default group ID of SRP public parameters.
   */
  const unsigned int getDefaultGroupId() const;

  /**
   * @brief Returns whether this class is acting as a server.
   * @return True if this is a server, false otherwise.
   */
  static bool getIsServerFlag();

private:
  /* private methods */

  /**
   * @brief This method will start the endpoints that the server
   * provides to his clients
   */
  void setupRoutes();

  /**
   * @brief This method is the entry point for the server URL address
   *
   * This method will serve as a confirmation that the server is up
   * and running at the root path
   */
  void rootEndpoint();

  /**
   * @brief This method runs the route that performs group search inside the
   * registration step initialization.
   *
   * This method runs the route that performs group search inside the
   * registration step, returning the agreed group ID and salt.
   */
  void handleRegisterInit();

  /**
   * @brief This method performs all the activities that allow the conclusion of
   * the registration at the Secure Remote Password protocol.
   *
   * This method performs all the activities that allow the conclusion of
   * the registration at the Secure Remote Password protocol, namely the
   * validation of the parameter v and acknowledge back to the client.
   */
  void handleRegisterComplete();

  /**
   * @brief This method runs the route that performs the initialization of the
   * Secure Remote Password protocol authentication step.
   *
   * This method runs the route that performs the Secure Remote Password
   * protocol initialization step, and the verifications and calculations
   * associated with that exchange.
   */
  void handleAuthenticationInit();

  /**
   * @brief This method runs the route that performs the conclusion of the
   * Secure Remote Password protocol authentication step.
   *
   * This method runs the route that performs the Secure Remote Password
   * protocol finalization step, and the verifications and calculations
   * associated with that exchange.
   */
  void handleAuthenticationComplete();

  /**
   * @brief This method perform the validation of the extracted v parameter
   * at the registration step.
   *
   * This method performs the validation of the extracted v parameter
   * at the registration step, it will test if v ∈ [1, N-1].
   *
   * @param clientId The clientId involved in this registration step.
   * @param vHex The v parameter in hexadecimal format.
   *
   * @return True if the validation passes, false otherwise.
   */
  bool vValidation(const std::string &clientId, const std::string &vHex);

  /**
   * @brief This method runs the route that provides the list of registered
   * users.
   *
   * This method runs the route that provides the list of registered users
   * who have completed the registration process.
   */
  void registeredUsersEndpoint();

  /* private fields */
  crow::SimpleApp _app;

  mutable std::mutex _secureRemotePasswordMapMutex;
  std::map<std::string, std::unique_ptr<SessionData>> _secureRemotePasswordMap;

  const int _portProduction{18080};
  const int _portTest{18081};

  std::thread _serverThread;
  const bool _debugFlag;

  const std::string _srpParametersFilename;
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _defaultGroupId;
  unsigned int _minGroupId, _maxGroupId;

  const std::map<std::string, unsigned int> _minSaltSizesMap;
  const std::unordered_map<std::string, EncryptionUtility::HashFn> _hashMap;
  static bool _isServerFlag;
};

#endif // SERVER_HPP
