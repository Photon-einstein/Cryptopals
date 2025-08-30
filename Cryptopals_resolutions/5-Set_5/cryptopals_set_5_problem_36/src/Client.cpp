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
Client::Client(const std::string &clientId, const bool debugFlag)
    : _clientId{clientId}, _debugFlag{debugFlag},
      _minSaltSizesMap{EncryptionUtility::getMinSaltSizes()} {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null.");
  }
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
/**
 * @brief This method sets the server's production port to a new one.
 *
 * This method sets the server's production port to a new one.
 *
 * @param portServerTest The port number to be used in production.
 *
 * @throw runtime_error if the portProduction is not a valid one.
 */
void Client::setProductionPort(const int portServerProduction) {
  if (portServerProduction < 1024 || portServerProduction > 49151) {
    throw std::runtime_error("Client log | setProductionPort(): "
                             "invalid production port number given, must be in "
                             "range [1024, 49151].");
  }
  _portServerProduction = portServerProduction;
}
/******************************************************************************/
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
void Client::setTestPort(const int portServerTest) {
  if (portServerTest < 1024 || portServerTest > 49151) {
    throw std::runtime_error(
        "Client log | setTestPort(): "
        "invalid port test number given, must be in range [1024, 49151].");
  }
  _portServerTest = portServerTest;
}
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
 * @brief This method returns the location of the file where the public
 * configurations of the Secure Remote Password protocol are available.
 *
 * @return Filename where the public configurations of the Secure Remote
 * Password protocol are available.
 */
const std::string &Client::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getSrpParametersFilenameLocation(): public SRP "
                             "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
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
  try {
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
    cpr::Response response =
        cpr::Post(cpr::Url{std::string("http://localhost:") +
                           std::to_string(portServerNumber) +
                           std::string("/groups/search")},
                  cpr::Header{{"Content-Type", "application/json"}},
                  cpr::Body{requestBody});
    if (_debugFlag) {
      printServerResponse(response);
    }
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | registration(): "
                               "registration failed");
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    const std::string extractedClientId =
        parsedJson.at("clientId").get<std::string>();
    const unsigned int extractedGroupId =
        parsedJson.at("groupId").get<unsigned int>();
    const std::string extractedGroupName =
        parsedJson.at("groupName").get<std::string>();
    const std::string extractedPrimeN =
        parsedJson.at("primeN").get<std::string>();
    const unsigned int extractedGeneratorG =
        parsedJson.at("generatorG").get<unsigned int>();
    const std::string extractedSalt = parsedJson.at("salt").get<std::string>();
    const std::string extractedSha = parsedJson.at("sha").get<std::string>();
    if (_debugFlag) {
      std::cout << "\n--- Client log | /groups/search server response "
                   "extracted data ---"
                << std::endl;
      std::cout << "\tClient ID: " << extractedClientId << std::endl;
      std::cout << "\tGroup ID: " << extractedGroupId << std::endl;
      std::cout << "\tGroup name: " << extractedGroupName << std::endl;
      std::cout << "\tPrime N: " << extractedPrimeN << std::endl;
      std::cout << "\tGenerator g: " << extractedGeneratorG << std::endl;
      std::cout << "\tSalt: " << extractedSalt << std::endl;
      std::cout << "\tSHA: " << extractedSha << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    // Client side server response validation
    const unsigned int minSaltSize =
        _minSaltSizesMap.at(_srpParametersMap.at(extractedGroupId)._hashName);
    if (extractedClientId != getClientId()) {
      throw std::runtime_error(
          "Client log | registration(): "
          "Client ID received does not match's client's one.");
    } else if (_srpParametersMap.find(extractedGroupId) ==
               _srpParametersMap.end()) {
      throw std::runtime_error("Client log | registration(): "
                               "Group ID received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._pHex !=
               extractedPrimeN) {
      throw std::runtime_error("Client log | registration(): "
                               "Prime N received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._g !=
               extractedGeneratorG) {
      throw std::runtime_error("Client log | registration(): "
                               "Generator g received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._hashName !=
               extractedSha) {
      throw std::runtime_error("Client log | registration(): "
                               "Hash name received not valid.");
    } else if (extractedSalt.size() < minSaltSize * 2) { /* salt is in hex */
      throw std::runtime_error("Client log | registration(): "
                               "Minimum salt size is not met.");
    }
    // Data storage
    _sessionData = std::make_unique<SessionData>(extractedGroupId,
                                                 extractedSalt, extractedSha);
    if (_sessionData.get() == nullptr) {
      throw std::runtime_error("Client log | registration(): "
                               "_sessionData value returned is null.");
    }
    return registrationResult;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    registrationResult = false;
    return registrationResult;
  }
}
/******************************************************************************/
/**
 * @brief This method will print the server response during the Secure Remote
 * Password protocol.
 *
 * This method will print the server response to the Secure Remote
 * Password protocol. The response is a json text, and it will be printed in a
 * structured way.
 *
 * @param response The response sent by the server during the execution
 * of the Secure Remote Password protocol.
 */
void Client::printServerResponse(const cpr::Response &response) {
  std::cout << "Status Code: " << response.status_code << "\n";
  std::cout << "Headers:\n";
  for (const auto &header : response.header) {
    std::cout << header.first << ": " << header.second << "\n";
  }
  std::cout << "Body:\n";
  if (response.text.empty()) {
    std::cout << "[Empty Body]\n";
  } else {
    try {
      nlohmann::json parsedJson = nlohmann::json::parse(response.text);
      std::cout << parsedJson.dump(2) << "\n"; // '2' for 2-space indentation
    } catch (const nlohmann::json::exception &e) {
      // Not valid JSON, print as raw text
      std::cout << response.text << "\n";
      std::cerr << "Warning: Body is not valid JSON, printing raw. Error: "
                << e.what() << "\n";
    }
  }
}
/******************************************************************************/
