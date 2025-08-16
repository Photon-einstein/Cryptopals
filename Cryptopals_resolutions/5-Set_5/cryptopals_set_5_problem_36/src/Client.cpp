#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <fmt/core.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include "./../include/Client.hpp"
#include "./../include/EncryptionUtility.hpp"

/* constructor / destructor */
Client::Client(const std::string &clientId, const bool debugFlag)
    : _clientId{clientId}, _debugFlag{debugFlag} {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null");
  }
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
/**
 * @brief This method return the client ID.
 *
 * This method return the client ID of a given client.
 *
 * @return A string, the client ID.
 * @throw runtime_error if the client ID is null.
 */
const std::string &Client::getClientId() const {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null");
  }
  return _clientId;
}
/******************************************************************************/
/**
 * @brief This method will return the production port of the server.
 *
 * @return The production port of the server to establish a connection.
 */
const int Client::getProductionPort() const { return _portServerProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * @return The test port of the server to establish a connection.
 */
const int Client::getTestPort() const { return _portServerTest; }
/******************************************************************************/
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
const bool Client::registration(const int portServerNumber,
                                const unsigned int groupId) {
  bool registrationResult{true};
  if (portServerNumber < 1023 || (portServerNumber != _portServerProduction &&
                                  portServerNumber != _portServerTest)) {
    throw std::runtime_error("Client log | registration(): "
                             "Invalid port server number used.");
  }
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}",
        "requestedGroup": "{}"
    }})",
      getClientId(), groupId);
  cpr::Response response = cpr::Post(
      cpr::Url{std::string("http://localhost:") +
               std::to_string(portServerNumber) + std::string("/registration")},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{requestBody});
  try {
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | registration(): "
                               "registration failed");
    }
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return registrationResult;
}
/******************************************************************************/
