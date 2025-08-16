#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "MessageExtractionFacility.hpp"
#include "SrpParametersLoader.hpp"

class Client {
public:
  /* constructor / destructor*/
  explicit Client(const std::string &clientId, const bool debugFlag);
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
