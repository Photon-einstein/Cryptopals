#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "MessageExtractionFacility.hpp"
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

private:
  /* private fields */
  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId{};
  const bool _debugFlag;
};

#endif // CLIENT_HPP
