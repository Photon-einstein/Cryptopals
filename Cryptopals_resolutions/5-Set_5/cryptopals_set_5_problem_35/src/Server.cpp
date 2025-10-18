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
 *
 */
Server::Server(const bool debugFlag) : _debugFlag{debugFlag} {
  boost::uuids::random_generator gen;
  _serverId += boost::uuids::to_string(gen());
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
  clearDiffieHellmanSessionData();
}
/******************************************************************************/
/**
 * @brief This method will start all the server's endpoint in a multi thread
 * environment.
 *
 * This method will start all the endpoints that the server provides to their
 * clients.
 */
void Server::runServer() {
  setupRoutes();
  _app.port(_portProduction).multithreaded().run();
}
/******************************************************************************/
/**
 * @brief This method will start all the server's endpoints in a multi thread
 * environment for a test scenario.
 *
 * This method will start all the endpoints that the server provides to their
 * clients, for a given test.
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
 * after the execution of the Diffie Hellman key exchange protocol.
 */
void Server::clearDiffieHellmanSessionData() {
  std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
  _diffieHellmanMap.clear();
}
/******************************************************************************/
/**
 * @brief This method will return the server's production port.
 *
 * This method will return the server's production port to establish a
 * connection.
 */
const int Server::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the server's test port.
 *
 * This method will return the server's test port to establish a
 * connection.
 */
const int Server::getTestPort() const { return _portTest; }
/******************************************************************************/
/**
 * @brief This method will return the Diffie Hellman's map.
 *
 * This method will return the Diffie Hellman's map of the server.
 *
 * @return The client's DH map.
 */
std::map<boost::uuids::uuid, std::unique_ptr<SessionData>> &
Server::getDiffieHellmanMap() {
  return _diffieHellmanMap;
}
/******************************************************************************/
/**
 * @brief This method will start the endpoints that the server
 * provides to his clients.
 *
 * This method will start the endpoints that the server
 * provides to his clients.
 */
void Server::setupRoutes() {
  rootEndpoint();
  keyExchangeRoute();
  getSessionsDataEndpoint();
  messageExchangeRoute();
}
/******************************************************************************/
/**
 * @brief This method is the entry point for the server URL address
 *
 * This method will serve as a confirmation that the server's URL is up
 * and running at the root path.
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
 * @brief This method runs the route that performs the Diffie Hellman's
 * key exchange protocol.
 *
 * This method runs the route that performs the Diffie Hellman's
 * key exchange protocol. It receives requests and makes all the calculations
 * to respond to the requests, creating a symmetric key for each connection
 * request.
 *
 * @throws std::runtime_error if there was an error in the keyExchangeRoute.
 */
void Server::keyExchangeRoute() {
  CROW_ROUTE(_app, "/keyExchange")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedClientId =
              parsedJson.at("clientId").get<std::string>();
          std::string extractedNonceClient =
              parsedJson.at("nonce").get<std::string>();
          std::string extractedPrimeP =
              parsedJson.at("diffieHellman").at("p").get<std::string>();
          std::string extractedGeneratorG =
              parsedJson.at("diffieHellman").at("g").get<std::string>();
          std::string extractedPublicKeyA = parsedJson.at("diffieHellman")
                                                .at("publicKeyA")
                                                .get<std::string>();
          if (_debugFlag) {
            std::cout
                << "\n--- Server log | Extracted Data from a new client ---"
                << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "\tClient nonce: " << extractedNonceClient
                      << std::endl;
            std::cout << "\tPrime p: " << extractedPrimeP << std::endl;
            std::cout << "\tGenerator g: " << extractedGeneratorG << std::endl;
            std::cout << "\tPublic Key A: " << extractedPublicKeyA << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
              MessageExtractionFacility::hexToUniqueBIGNUM(extractedPublicKeyA);
          boost::uuids::uuid sessionId = generateUniqueSessionId();
          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          _diffieHellmanMap[sessionId] = std::make_unique<SessionData>(
              _nonceSize, extractedNonceClient, extractedClientId, _debugFlag,
              _ivLength, extractedPrimeP, extractedGeneratorG);
          _diffieHellmanMap[sessionId]->_derivedKeyHex =
              _diffieHellmanMap[sessionId]->_diffieHellman->deriveSharedSecret(
                  extractedPublicKeyA,
                  _diffieHellmanMap[sessionId]->_serverNonceHex,
                  _diffieHellmanMap[sessionId]->_clientNonceHex);
          res["message"] = _diffieHellmanMap[sessionId]
                               ->_diffieHellman->getConfirmationMessage();
          res["sessionId"] = boost::uuids::to_string(sessionId);
          res["diffieHellman"] = {
              {"p", _diffieHellmanMap[sessionId]->_diffieHellman->getPrimeP()},
              {"g",
               _diffieHellmanMap[sessionId]->_diffieHellman->getGeneratorG()},
              {"publicKeyB",
               _diffieHellmanMap[sessionId]->_diffieHellman->getPublicKey()}};
          res["nonce"] = _diffieHellmanMap[sessionId]->_serverNonceHex;
          // confirmation payload
          std::string serverConfirmationMessage =
              _diffieHellmanMap[sessionId]
                  ->_diffieHellman->getConfirmationMessage() +
              " with " + _serverId;
          nlohmann::json confirmationPayload = {
              {"sessionId", boost::uuids::to_string(sessionId)},
              {"clientId", extractedClientId},
              {"clientNonce", extractedNonceClient},
              {"serverNonce", _diffieHellmanMap[sessionId]->_serverNonceHex},
              {"message", serverConfirmationMessage}};
          const std::string confirmationString = confirmationPayload.dump();
          std::string encryptedConfirmationHex =
              EncryptionUtility::encryptMessageAes256CbcMode(
                  confirmationString,
                  _diffieHellmanMap[sessionId]
                      ->_diffieHellman->getSymmetricKey(),
                  _diffieHellmanMap[sessionId]->_iv);
          res["confirmation"] = {
              {"ciphertext", encryptedConfirmationHex},
              {"iv", MessageExtractionFacility::toHexString(
                         _diffieHellmanMap[sessionId]->_iv)}};
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
 * @brief This method runs the route that performs the message exchange using
 * symmetric encryption after the Diffie Hellman's key exchange protocol has
 * been completed.
 *
 * This method runs the route that performs the message exchange using
 * symmetric encryption after the Diffie Hellman's key exchange protocol has
 * been completed. It receives messages from clients, checks the validity of
 * the session ID and if valid, sends back a confirmation response.
 *
 * @throws std::runtime_error if there is an error in MessageExchangeRoute.
 */
void Server::messageExchangeRoute() {
  CROW_ROUTE(_app, "/messageExchange")
      .methods("POST"_method)([&](const crow::request &req) {
        crow::json::wvalue res;
        try {
          nlohmann::json parsedJson = nlohmann::json::parse(req.body);
          std::string extractedSessionId =
              parsedJson.at("sessionId").get<std::string>();
          std::string extractedIv = parsedJson.at("iv").get<std::string>();
          std::string extractedCiphertext =
              parsedJson.at("ciphertext").get<std::string>();
          boost::uuids::string_generator gen;
          boost::uuids::uuid extractedSessionIdUuidFormat =
              gen(extractedSessionId);
          // check if session ID already exists
          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          if (_diffieHellmanMap.find(extractedSessionIdUuidFormat) ==
              _diffieHellmanMap.end()) {
            throw std::runtime_error("Server log | MessageExchangeRoute(): "
                                     "Session ID: " +
                                     extractedSessionId + " not valid");
          }
          // convert iv to bytes and store it
          _diffieHellmanMap[extractedSessionIdUuidFormat]->_iv =
              MessageExtractionFacility::hexToBytes(extractedIv);
          const std::string plaintext =
              EncryptionUtility::decryptMessageAes256CbcMode(
                  extractedCiphertext,
                  _diffieHellmanMap[extractedSessionIdUuidFormat]
                      ->_diffieHellman->getSymmetricKey(),
                  _diffieHellmanMap[extractedSessionIdUuidFormat]->_iv);
          if (_debugFlag) {
            std::cout
                << "Server log | MessageExchangeRoute() - decrypted plaintext: "
                << plaintext << std::endl;
          }
          // build server's confirmation
          std::string serverConfirmationMessage =
              std::string("Hello from server ID: ") + _serverId +
              " at session ID: " + extractedSessionId +
              +" message received from client: '" + plaintext + "'";
          _diffieHellmanMap[extractedSessionIdUuidFormat]->_iv =
              EncryptionUtility::generateRandomIV(_nonceSize);
          // encrypt server's confirmation message
          std::string serverConfirmationMessageEncrypted =
              EncryptionUtility::encryptMessageAes256CbcMode(
                  serverConfirmationMessage,
                  _diffieHellmanMap[extractedSessionIdUuidFormat]
                      ->_diffieHellman->getSymmetricKey(),
                  _diffieHellmanMap[extractedSessionIdUuidFormat]->_iv);
          // build confirmation response
          res["sessionId"] = extractedSessionId;
          res["confirmation"] = {
              {"ciphertext", serverConfirmationMessageEncrypted},
              {"iv",
               MessageExtractionFacility::toHexString(
                   _diffieHellmanMap[extractedSessionIdUuidFormat]->_iv)}};
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
 * @brief This method runs the route that gets all the current available
 * sessions created using the Diffie Hellman's key exchange protocol.
 *
 * This method runs the route that gets all the current available sessions
 * created using the Diffie Hellman's key exchange protocol. It outputs all the
 * session data in json format.
 */
void Server::getSessionsDataEndpoint() {
  CROW_ROUTE(_app, "/sessionsData")
      .methods("GET"_method)([&](const crow::request &req) {
        try {
          crow::json::wvalue res;
          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          for (const auto &entry : _diffieHellmanMap) {
            const auto &sessionId = entry.first;
            const auto &sessionData = entry.second;
            std::string sessionIdStr = boost::uuids::to_string(sessionId);
            res[sessionIdStr] = {{"sessionId", sessionIdStr},
                                 {"clientId", sessionData->_clientId},
                                 {"clientNonce", sessionData->_clientNonceHex},
                                 {"serverNonce", sessionData->_serverNonceHex},
                                 {"derivedKey", sessionData->_derivedKeyHex},
                                 {"iv", MessageExtractionFacility::toHexString(
                                            sessionData->_iv)}};
          }
          return crow::response(200, res);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["error"] = e.what();
          return crow::response(500, err);
        }
      });
}
/******************************************************************************/
/**
 * @brief This method will generate an unique session's ID.
 *
 * This method will generate an unique session's ID for a given connection
 * request.
 *
 * @return An unique session's ID to be used.
 */
boost::uuids::uuid Server::generateUniqueSessionId() {
  bool uniqueSessionId{false};
  boost::uuids::random_generator gen;
  boost::uuids::uuid sessionId;
  std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
  do {
    sessionId = gen();
    if (_diffieHellmanMap.find(sessionId) == _diffieHellmanMap.end()) {
      uniqueSessionId = true;
    }
  } while (!uniqueSessionId);
  return sessionId;
}
/******************************************************************************/
