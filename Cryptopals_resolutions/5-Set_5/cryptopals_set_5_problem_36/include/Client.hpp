#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "MessageExtractionFacility.hpp"
#include "SessionData.hpp"
#include "SrpParametersLoader.hpp"

class Client {
public:
  /* constructor / destructor*/

  /**
   * @brief This method will execute the constructor of the Client object.
   *
   * This method will perform the constructor of the Client object when a group
   * name is used in its constructor.
   *
   * @param clientId The client id to be used by this client.
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   *
   * @throw runtime_error if clientId is empty.
   */
  explicit Client(const std::string &clientId, const bool debugFlag);

  /**
   * @brief This method will perform the destruction of the Client object.
   *
   * This method will perform the destruction of the Client object, releasing
   * all the resources and memory used.
   */
  ~Client();

  /* public methods */

  /**
   * @brief This method sets the server's production port to a new one.
   *
   * This method sets the server's production port to a new one.
   *
   * @param portServerTest The port number to be used in production.
   *
   * @throw runtime_error if the portProduction is not a valid one.
   */
  void setProductionPort(const int portProduction);

  /**
   * @brief This method sets the server's test port to a new one.
   *
   * This method sets the server's test port to a new one, used only for
   * test purposes.
   *
   * @param portServerTest The port number to be used in the test scenario.
   *
   * @throw runtime_error if the portServerTest is not a valid one.
   */
  void setTestPort(const int portServerTest);

  /**
   * @brief This method return the client ID.
   *
   * This method return the client ID of a given client.
   *
   * @return A string, the client ID.
   * @throw runtime_error if the client ID is null.
   */
  const std::string &getClientId() const;

  /**
   * @brief This method will return the production port of the server.
   *
   * @return The production port of the server to establish a connection.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the test port of the server.
   *
   * @return The test port of the server to establish a connection.
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
   * @brief This method will perform the registration step with a given
   * server.
   *
   * This method perform the registration step with a given server.
   * It will propose a certain group ID that can be accepted or rejected
   * by the server, in the latter case it would be overwritten during this
   * step.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   * @param groupId The group ID that the client is proposing to the client.
   *
   * @return True if the registration succeed, false otherwise.
   */
  const bool registration(const int portServerNumber,
                          const unsigned int groupId = 1);

  /**
   * @brief This method will perform the authentication step with a given
   * server.
   *
   * This method perform the authentication step with a given server.
   * It is assumed that the registration was already completed at a previous
   * time.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   *
   * @return True if the authentication succeed, false otherwise.
   */
  const bool authentication(const int portServerNumber);

  /**
   * @brief Returns whether this class is acting as a server.
   * @return True if this is a server, false otherwise.
   */
  static bool getIsServerFlag();

  static std::string calculateX(const std::string &hash,
                                const std::string &salt,
                                const std::string &password);

private:
  /* private methods */

  /**
   * @brief This method will perform the first step of the registration
   * with a given server.
   *
   * This method perform the first step of the registration with a given
   * server. It will propose a certain group ID that can be accepted
   * or rejected by the server, in the latter case it would be overwritten
   * during this step.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   * @param groupId The group ID of this session.
   *
   * @return True if the registrationInit succeed, false otherwise.
   */
  const bool registrationInit(const int portServerNumber,
                              const unsigned int groupId);

  /**
   * @brief This method will perform the last step of the registration
   * with a given server.
   *
   * This method perform the last step of the registration step with a
   * given server. It will perform the computation of x and v and then
   * send to the server U and v.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   * @param groupId The group ID of this session.
   *
   * @return True if the registrationComplete succeed, false otherwise.
   */
  const bool registrationComplete(const int portServerNumber,
                                  const unsigned int groupId);

  /**
   * @brief This method will perform the first step of the authentication
   * with a given server.
   *
   * This method perform the first step of the authentication with a given
   * server. It will perform the calculations and verifications involved
   * at the first leg of the authentication of SRP protocol.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   *
   * @return True if the authenticationInit succeed, false otherwise.
   */
  const bool authenticationInit(const int portServerNumber);

  /**
   * @brief This method will print the server response during the Secure
   * Remote Password protocol.
   *
   * This method will print the server response to the Secure Remote
   * Password protocol. The response is a json text, and it will be printed
   * in a structured way.
   *
   * @param response The response sent by the server during the execution
   * of the Secure Remote Password protocol.
   */
  static void printServerResponse(const cpr::Response &response);

  /* private fields */

  int _portServerProduction{18080};
  int _portServerTest{18081};

  const std::string _clientId{};
  const bool _debugFlag;

  const std::string _srpParametersFilename{"../input/SrpParameters.json"};
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;

  const std::map<std::string, unsigned int> _minSaltSizesMap;
  std::unique_ptr<SessionData> _sessionData;
  const unsigned int _passwordSize{20}; // bytes
  const std::string _serverConfirmationMessage{"Ack"};
  static bool _isServerFlag;
};

#endif // CLIENT_HPP
