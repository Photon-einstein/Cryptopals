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
    : _debugFlag{debugFlag},
      _minSaltSizesMap{EncryptionUtility::getMinSaltSizes()},
      _hashMap{EncryptionUtility::getHashMap()} {
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
  const unsigned int minimumValueGroupId{3};
  _minGroupId = _srpParametersMap.begin()->first;
  _maxGroupId = _srpParametersMap.rbegin()->first;
  _defaultGroupId =
      (defaultGroupId >= _minGroupId && defaultGroupId <= _maxGroupId)
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
 * @brief This method will clear all the sessions in memory.
 *
 * This method will clear all the sessions in memory that were created
 * after the execution of the Secure Remote Password protocol.
 */
void Server::clearSecureRemotePasswordMap() {
  std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
  _secureRemotePasswordMap.clear();
}
/******************************************************************************/
/**
 * @brief This method will return the production port of the server.
 *
 * This method will return the production port of the server to establish a
 * connection.
 *
 * @return The production port of the server.
 */
const int Server::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * This method will return the test port of the server to establish a
 * connection.
 *
 * @return The test port of the server.
 */
const int Server::getTestPort() const { return _portTest; }
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
/**
 * @brief This method returns the default group ID of SRP public parameters.
 * This value is used when the user does not provide a group ID during the
 * Secure remote password protocol.
 *
 * @return The default group ID of SRP public parameters.
 */
const unsigned int Server::getDefaultGroupId() { return _defaultGroupId; }
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
  handleRegisterInit();
  handleRegisterComplete();
  handleAuthenticationInit();
  registeredUsersEndpoint();
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
 * registration step initialization.
 *
 * This method runs the route that performs group search inside the
 * registration step, returning the agreed group id and the salt.
 */
void Server::handleRegisterInit() {
  CROW_ROUTE(_app, "/srp/register/init")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          unsigned int extractedGroupId;
          if (!parsedJson.contains("requestedGroup") ||
              !parsedJson["requestedGroup"].is_number_unsigned()) {
            extractedGroupId = _defaultGroupId;
          } else {
            extractedGroupId =
                parsedJson.at("requestedGroup").get<unsigned int>();
          }
          // group id validation
          extractedGroupId = (extractedGroupId >= _defaultGroupId &&
                              extractedGroupId <= _maxGroupId)
                                 ? extractedGroupId
                                 : _defaultGroupId;
          std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
          // cliend ID validation
          if (extractedClientId.size() == 0) {
            throw std::runtime_error("Server log | handleRegisterInit(): "
                                     "ClientId is null");
          } else if (_secureRemotePasswordMap.find(extractedClientId) !=
                         _secureRemotePasswordMap.end() &&
                     _secureRemotePasswordMap[extractedClientId]
                         ->registrationComplete) {
            crow::json::wvalue err;
            err["message"] = "Server log | handleRegisterInit(): Conflict, "
                             "client is already registered";
            return crow::response(409, err);
          }
          if (_debugFlag) {
            std::cout << "\n--- Server log | Extracted Data from a new client "
                         "request registration ---"
                      << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "\tRequested group: " << extractedGroupId << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          const unsigned int minSaltSize = _minSaltSizesMap.at(
              _srpParametersMap.at(extractedGroupId)._hashName);
          const std::string salt =
              EncryptionUtility::generateCryptographicNonce(minSaltSize);
          const std::string hash =
              _srpParametersMap[extractedGroupId]._hashName;
          _secureRemotePasswordMap[extractedClientId] =
              std::make_unique<SessionData>(extractedGroupId, salt, hash);
          // reply to the client with the group ID parameters and the salt s
          res["clientId"] = extractedClientId;
          res["groupId"] = extractedGroupId;
          res["groupName"] = _srpParametersMap[extractedGroupId]._groupName;
          res["primeN"] = _srpParametersMap[extractedGroupId]._nHex;
          res["generatorG"] = _srpParametersMap[extractedGroupId]._g;
          res["sha"] = _srpParametersMap[extractedGroupId]._hashName;
          res["salt"] = salt;
          return crow::response(201, res);
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(404, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") +
              e.what();
          return crow::response(400, err);
        }
      });
}
/******************************************************************************/
/**
 * @brief This method performs all the activities that allow the conclusion of
 * the registration at the Secure Remote Password protocol.
 *
 * This method performs all the activities that allow the conclusion of
 * the registration at the Secure Remote Password protocol, namely the
 * validation of the parameter v and acknowledge back to the client.
 */
void Server::handleRegisterComplete() {
  CROW_ROUTE(_app, "/srp/register/complete")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          std::string extractedVHex = parsedJson.at("v").get<std::string>();
          // client ID validation
          std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
          if (extractedClientId.empty()) {
            throw std::runtime_error("Server log | handleRegisterComplete(): "
                                     "ClientId is null");
          } else if (_secureRemotePasswordMap.find(extractedClientId) ==
                     _secureRemotePasswordMap.end()) {
            throw std::runtime_error("Server log | handleRegisterComplete(): "
                                     "ClientId not found.");
          } else if (_secureRemotePasswordMap.find(extractedClientId) !=
                         _secureRemotePasswordMap.end() &&
                     _secureRemotePasswordMap[extractedClientId]
                         ->registrationComplete) {
            crow::json::wvalue err;
            err["message"] = "Server log | handleRegisterInit(): Conflict, "
                             "client is already registered";
            return crow::response(409, err);
          }
          // v validation
          if (extractedVHex.empty()) {
            throw std::runtime_error("Server log | handleRegisterComplete(): "
                                     "extractedVHex is null");
          }
          const bool vValidationResult =
              vValidation(extractedClientId, extractedVHex);
          if (!vValidationResult) {
            throw std::runtime_error("Server log | handleRegisterComplete(): v "
                                     "received is not valid for client: " +
                                     extractedClientId);
          }
          // store the v parameter
          _secureRemotePasswordMap[extractedClientId]->_vHex = extractedVHex;
          // reply to the client with the acknowledgment of successful
          // registration completion
          _secureRemotePasswordMap[extractedClientId]->registrationComplete =
              true;
          res["confirmation"] = "Ack";
          return crow::response(201, res);
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(404, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") +
              e.what();
          return crow::response(400, err);
        }
      });
}
/******************************************************************************/
/**
 * @brief This method runs the route that performs the initialization of the
 * Secure Remote Password protocol authentication step.
 *
 * This method runs the route that performs the Secure Remote Password protocol
 * initialization step, and the verifications and calculations associated with
 * that exchange.
 */
void Server::handleAuthenticationInit() {
  CROW_ROUTE(_app, "/srp/auth/init")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          if (_debugFlag) {
            std::cout << "\n--- Server log | Extracted Data from a new client "
                         "request authentication ---"
                      << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          // client id verification
          std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
          if (extractedClientId.empty()) {
            throw std::runtime_error("Server log | handleAuthenticationInit(): "
                                     "Client received is null");
          } else if (_secureRemotePasswordMap.find(extractedClientId) ==
                     _secureRemotePasswordMap.end()) {
            throw std::runtime_error("Server log | handleAuthenticationInit(): "
                                     "Client " +
                                     extractedClientId +
                                     " has not registered before.");
          } else if (!_secureRemotePasswordMap[extractedClientId]
                          ->registrationComplete) {
            throw std::runtime_error("Server log | handleAuthenticationInit(): "
                                     "Client " +
                                     extractedClientId +
                                     " has not a completed registration.");
          }
          const unsigned int groupId{
              _secureRemotePasswordMap[extractedClientId]->_groupId};
          const long unsigned int saltSize{
              _secureRemotePasswordMap[extractedClientId]->_salt.size()};
          const long unsigned int minSaltSize{
              _minSaltSizesMap.at(_srpParametersMap.at(groupId)._hashName)};
          const std::string extractedVHex{
              _secureRemotePasswordMap[extractedClientId]->_vHex};
          if (_srpParametersMap.find(groupId) == _srpParametersMap.end()) {
            throw std::runtime_error("Server log | handleAuthenticationInit(): "
                                     "Client " +
                                     extractedClientId +
                                     ": stored group ID is not valid.");
          } else if (saltSize < minSaltSize) {
            throw std::runtime_error(
                "Server log | handleAuthenticationInit(): "
                "Client " +
                extractedClientId +
                ": stored salt doesn't meet minimum size criteria.");
          } else if (!vValidation(extractedClientId, extractedVHex)) {
            throw std::runtime_error(
                "Server log | handleAuthenticationInit(): "
                "Client " +
                extractedClientId +
                ": stored v doesn't meet the minimum criteria.");
          }
          // private key generation
          const unsigned int minPrivateKeyBits =
              _secureRemotePasswordMap[extractedClientId]
                  ->_secureRemotePassword->getMinSizePrivateKey();
          _secureRemotePasswordMap[extractedClientId]->_privateKeyHex =
              EncryptionUtility::generatePrivateKey(
                  _srpParametersMap.at(groupId)._nHex, minPrivateKeyBits);
          if (_debugFlag) {
            std::cout << "\n--- Server log | Private key generated at the "
                         "authentication phase---"
                      << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout
                << "\tPrivate key: "
                << _secureRemotePasswordMap[extractedClientId]->_privateKeyHex
                << std::endl;
            std::cout << "----------------------" << std::endl;
          }
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(404, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") +
              e.what();
          return crow::response(400, err);
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method perform the validation of the extracted v parameter
 * at the registration step.
 *
 * This method perform the validation of the extracted v parameter
 * at the registration step, it will test if v ∈ ]0, N[.
 *
 * @param clientId The clientId involved in this registration step.
 * @param vHex The v parameter in hexadecimal format.
 *
 * @return True if the validation passes, false otherwise.
 */
bool Server::vValidation(const std::string &clientId, const std::string &vHex) {
  try {
    if (clientId.empty()) {
      throw std::runtime_error("Server log | vValidation(): "
                               "ClientId is null");
    } else if (_secureRemotePasswordMap.find(clientId) ==
               _secureRemotePasswordMap.end()) {
      throw std::runtime_error("Server log | vValidation(): "
                               "ClientId not found.");
    } else if (vHex.empty()) {
      throw std::runtime_error("Server log | vValidation(): "
                               "vHex is null");
    }
    const std::string &nHex =
        _srpParametersMap[_secureRemotePasswordMap[clientId]->_groupId]._nHex;
    BIGNUM *vBn = nullptr;
    BIGNUM *nBn = nullptr;
    if (!BN_hex2bn(&vBn, vHex.c_str()) || !BN_hex2bn(&nBn, nHex.c_str())) {
      BN_free(vBn);
      BN_free(nBn);
      throw std::runtime_error(
          "Server log | handleRegisterComplete(): Failed to "
          "convert v or N to BIGNUM.");
    }
    if (BN_is_zero(vBn) || BN_is_negative(vBn) || BN_cmp(vBn, nBn) >= 0) {
      BN_free(vBn);
      BN_free(nBn);
      throw std::runtime_error(
          "Server log | handleRegisterComplete(): v is not "
          "in the valid range (0 < v < N) for client: " +
          clientId);
    }
    BN_free(vBn);
    BN_free(nBn);
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
  return true;
}
/******************************************************************************/
/**
 * @brief This method runs the route that provides the list of registered users.
 *
 * This method runs the route that provides the list of registered users
 * who have completed the registration process.
 */
void Server::registeredUsersEndpoint() {
  CROW_ROUTE(_app, "/srp/registered/users").methods("GET"_method)([this]() {
    crow::json::wvalue res;
    try {
      std::vector<std::string> registeredUsers;
      {
        std::lock_guard<std::mutex> lock(_secureRemotePasswordMapMutex);
        for (const auto &pair : _secureRemotePasswordMap) {
          if (pair.second && pair.second->registrationComplete) {
            registeredUsers.push_back(pair.first);
          }
        }
      }
      res["users"] = registeredUsers;
      return crow::response(200, res);
    } catch (const nlohmann::json::exception &e) {
      crow::json::wvalue err;
      err["message"] =
          std::string("Server log | JSON parsing error: ") + e.what();
      return crow::response(400, err);
    } catch (const std::exception &e) {
      crow::json::wvalue err;
      err["message"] =
          std::string("Server log | An unexpected error occurred: ") + e.what();
      return crow::response(400, err);
    }
  });
}
/******************************************************************************/
