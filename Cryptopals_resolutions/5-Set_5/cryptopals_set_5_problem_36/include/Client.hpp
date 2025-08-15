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
   * This method will return the production port of the server to establish a
   * connection.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the test port of the server.
   *
   * This method will return the test port of the server to establish a
   * connection.
   */
  const int getTestPort() const;

private:
  /* private fields */
  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId{};
  const bool _debugFlag;
};

#endif // CLIENT_HPP
