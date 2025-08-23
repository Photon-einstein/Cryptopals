#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

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
Server::Server(const bool debugFlag, const unsigned int defaultGroupId)
    : _debugFlag{debugFlag} {
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
  const unsigned int minimumValueGroupId{3};
  _minGroupId = _srpParametersMap.begin()->first;
  _maxGroupId = _srpParametersMap.rbegin()->first;
  _defaultGroupId =
      (defaultGroupId >= minimumValueGroupId && defaultGroupId <= _maxGroupId)
          ? defaultGroupId
          : minimumValueGroupId;
}
/******************************************************************************/
/**
 * @brief This method will perform the destruction of the Server object.
 *
 * This method will perform the destruction of the Server object, releasing
 * all the resources and memory used.
 */
Server::~Server() {
  // server graceful stop
  _app.stop();
  if (_serverThread.joinable()) {
    _serverThread.join(); // Wait for thread to finish
  }
}
/******************************************************************************/
/**
 * @brief This method will start all the server endpoints in a multi thread
 * environment
 *
 * This method will start all the endpoints that the server provides to their
 * clients
 */
void Server::runServer() {
  setupRoutes();
  _app.port(_portProduction).multithreaded().run();
}
/******************************************************************************/
/**
 * @brief This method will start all the server endpoints in a multi thread
 * environment for a test scenario
 *
 * This method will start all the endpoints that the server provides to their
 * clients, for a given test
 */
void Server::runServerTest() {
  _serverThread = std::thread([this]() {
    setupRoutes();
    _app.port(_portTest).multithreaded().run();
  }); // Let it live until process ends
}
/******************************************************************************/
/**
 * @brief This method will return the production port of the server.
 *
 * This method will return the production port of the server to establish a
 * connection.
 */
const int Server::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * This method will return the test port of the server to establish a
 * connection.
 */
const int Server::getTestPort() const { return _portTest; }
/******************************************************************************/
/**
 * @brief This method will start the endpoints that the server
 * provides to his clients
 *
 * This method will start the endpoints that the server
 * provides to his clients, namely the root endpoint and the signature
 * verification endpoint
 */
void Server::setupRoutes() {
  rootEndpoint();
  getGroupsData();
  authenticationRoute();
}
/******************************************************************************/
/**
 * @brief This method is the entry point for the server URL address
 *
 * This method will serve as a confirmation that the server URL is up
 * and running at the root path
 */
void Server::rootEndpoint() {
  CROW_ROUTE(_app, "/").methods("GET"_method)([&]() {
    crow::json::wvalue rootMessage;
    rootMessage["message"] =
        std::string("Server log | Root endpoint, server up and running");
    return crow::response(200, rootMessage);
  });
}
/******************************************************************************/
/**
 * @brief This method runs the route that performs group search inside the
 * registration step.
 *
 * This method runs the route that performs group search inside the
 * registration step, returning the agreed group id and the salt.
 */
void Server::getGroupsData() {
  CROW_ROUTE(_app, "/groups/search")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          unsigned int extractedGroupId =
              parsedJson.contains("reguestedGroup")
                  ? parsedJson["requestedGroup"].get<unsigned int>()
                  : _defaultGroupId;
          // group id validation
          extractedGroupId = (extractedGroupId >= _defaultGroupId &&
                              extractedGroupId <= _maxGroupId)
                                 ? extractedGroupId
                                 : _defaultGroupId;
          // cliend ID validation
          if (extractedClientId.size() == 0) {
            throw std::runtime_error("Server log | registration(): "
                                     "Client ID is null");
          }
          if (_debugFlag) {
            std::cout << "\n--- Server log | Extracted Data from a new client "
                         "request registration ---"
                      << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "\tRequested group: " << extractedGroupId << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          const std::string salt =
              EncryptionUtility::generateCryptographicNonce(_saltSize);
          const std::string hash =
              _srpParametersMap[extractedGroupId]._hashName;
          std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
          _secureRemotePasswordMap.at(extractedClientId) =
              std::make_unique<SessionData>(extractedGroupId, salt, hash);
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(400, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") +
              e.what();
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method runs the route that performs the Secure Remote Password
 * protocol authentication.
 *
 * This method runs the route that performs the Secure Remote Password protocol.
 * It receives requests and make all the calculations to response to the
 * requests, creating a symmetric key for each connection request, after
 * performing the authentication.
 */
void Server::authenticationRoute() {
  CROW_ROUTE(_app, "/authentication")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          if (_debugFlag) {
            std::cout << "\n--- Server log | Extracted Data from a new client "
                         "request connection ---"
                      << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "----------------------" << std::endl;
          }
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(400, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") +
              e.what();
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method returns the location of the file where the public
 * configurations of the Secure Remote Password protocol are available.
 *
 * @return Filename where the public configurations of the Secure Remote
 * Password protocol are available.
 */
const std::string &Server::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getSrpParametersFilenameLocation(): public SRP "
                             "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
/******************************************************************************/
