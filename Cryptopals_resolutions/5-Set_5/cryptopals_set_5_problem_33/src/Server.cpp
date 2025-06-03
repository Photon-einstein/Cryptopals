#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/EncryptionUtility.hpp"
#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag) : _debugFlag{debugFlag} {}
/******************************************************************************/
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
 * @brief This method will start the endpoints that the server
 * provides to his clients
 *
 * This method will start the endpoints that the server
 * provides to his clients, namely the root endpoint and the signature
 * verification endpoint
 */
void Server::setupRoutes() {
  rootEndpoint();
  keyExchangeRoute();
  getSessionsDataEndpoint();
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
        "Server log | Root endpoint, server up and running";
    return crow::response(200, rootMessage);
  });
}
/******************************************************************************/
/**
 * @brief This method runs the route that performs the Diffie Hellman
 * key exchange protocol.
 *
 * This method runs the route that performs the Diffie Hellman
 * key exchange protocol. I receives requests and make all the calculations
 * to response to the requests, creating a symmetric key for each connection
 * request.
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
          std::string extractedGroupName =
              parsedJson.at("diffieHellman").at("groupName").get<std::string>();
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
            std::cout << "\tGroup Name: " << extractedGroupName << std::endl;
            std::cout << "\tPublic Key A: " << extractedPublicKeyA << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
              MessageExtractionFacility::hexToUniqueBIGNUM(extractedPublicKeyA);
          boost::uuids::uuid sessionId = generateUniqueSessionId();

          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          _diffieHellmanMap[sessionId] = std::make_unique<SessionData>(
              _nonceSize, extractedNonceClient, extractedClientId, _debugFlag,
              _ivLength);

          _diffieHellmanMap[sessionId]->_derivedKeyHex =
              _diffieHellmanMap[sessionId]->_diffieHellman->deriveSharedSecret(
                  extractedPublicKeyA,
                  _diffieHellmanMap[sessionId]->_serverNonceHex,
                  _diffieHellmanMap[sessionId]->_clientNonceHex);

          res["message"] = "Diffie Hellman keys setup successfully!";
          res["sessionId"] = boost::uuids::to_string(sessionId);
          res["diffieHellman"] = {
              {"groupName",
               _diffieHellmanMap[sessionId]->_diffieHellman->getGroupName()},
              {"publicKeyB",
               _diffieHellmanMap[sessionId]->_diffieHellman->getPublicKey()}};
          res["nonce"] = _diffieHellmanMap[sessionId]->_serverNonceHex;
          // confirmation payload
          nlohmann::json confirmationPayload = {
              {"sessionId", boost::uuids::to_string(sessionId)},
              {"clientId", extractedClientId},
              {"clientNonce", extractedNonceClient},
              {"serverNonce", _diffieHellmanMap[sessionId]->_serverNonceHex},
              {"message", "Key exchange complete"}};
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
 * @brief This method will generate a unique session id.
 *
 * This method will generate a unique session id for a given connection
 * request.
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
