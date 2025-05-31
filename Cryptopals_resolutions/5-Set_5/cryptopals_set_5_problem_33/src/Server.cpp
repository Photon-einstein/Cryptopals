#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

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
 * @brief This method is the entry point for the server URL address
 *
 * This method will serve as a confirmation that the server URL is up
 * and running at the root path
 */
void Server::rootEndpoint() {
  CROW_ROUTE(_app, "/").methods("GET"_method)([&]() {
    crow::json::wvalue rootMessage;
    rootMessage["message"] = "Server log | Root endpoint, server up and running";
    return crow::response(200, rootMessage);
  });
}
/******************************************************************************/
void Server::setupRoutes() {
  rootEndpoint();
  keyExchangeRoute();
}
/******************************************************************************/
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
            std::cout << "\n--- Server log | Extracted Data from a new client ---" << std::endl;
            std::cout << "\tClient ID: " << extractedClientId << std::endl;
            std::cout << "\tClient nonce: " << extractedNonceClient << std::endl;
            std::cout << "\tGroup Name: " << extractedGroupName << std::endl;
            std::cout << "\tPublic Key A: " << extractedPublicKeyA << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
              MessageExtractionFacility::hexToUniqueBIGNUM(extractedPublicKeyA);
          boost::uuids::uuid sessionId = generateUniqueSessionId();
          _diffieHellmanMap[sessionId] = std::make_unique<SessionData>(
              _nonceSize, extractedNonceClient, extractedClientId, _debugFlag);
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
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] = std::string("Server log | JSON parsing error: ") + e.what();
          return crow::response(400, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Server log | An unexpected error occurred: ") + e.what();
        }
        return crow::response(201, res);
      });
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
void Server::runServerTest() {
  _serverThread = std::thread([this]() {
    setupRoutes();
    _app.port(_portTest).multithreaded().run();
  }); // Let it live until process ends
}
/******************************************************************************/
boost::uuids::uuid Server::generateUniqueSessionId() {
  bool uniqueSessionId{false};
  boost::uuids::random_generator gen;
  boost::uuids::uuid sessionId;
  do {
    sessionId = gen();
    if (_diffieHellmanMap.find(sessionId) == _diffieHellmanMap.end()) {
      uniqueSessionId = true;
    }
  } while (!uniqueSessionId);
  return sessionId;
}
/******************************************************************************/