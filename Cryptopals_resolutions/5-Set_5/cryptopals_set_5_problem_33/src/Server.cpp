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
    rootMessage["message"] = "Root endpoint, Server up and running";
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
        if (_debugFlag) {
          std::cout << "Received request body:\n" << req.body << std::endl;
        }
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
            std::cout << "\n--- Extracted Data ---" << std::endl;
            std::cout << "Client ID: " << extractedClientId << std::endl;
            std::cout << "Nonce: " << extractedNonceClient << std::endl;
            std::cout << "Group Name: " << extractedGroupName << std::endl;
            std::cout << "Public Key A: " << extractedPublicKeyA << std::endl;
            std::cout << "----------------------" << std::endl;
          }
          MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
              MessageExtractionFacility::hexToUniqueBIGNUM(extractedPublicKeyA);
          boost::uuids::uuid sessionId = generateUniqueSessionId();
          _diffieHellmanMap[sessionId] = std::make_unique<SessionData>(
              _nonceSize, extractedNonceClient, extractedClientId);
          if (_debugFlag) {
            std::cout << "Server log | sessionId " << sessionId
                      << " --> clientId: " << extractedClientId
                      << " | Nonce server (hex): "
                      << _diffieHellmanMap[sessionId]->_serverNonceHex
                      << "\n\t| Nonce client (hex): "
                      << _diffieHellmanMap[sessionId]->_clientNonceHex
                      << std::endl;
          }
          _diffieHellmanMap[sessionId]->_derivedKeyHex =
              _diffieHellmanMap[sessionId]->_diffieHellman->deriveSharedSecret(
                  extractedPublicKeyA,
                  _diffieHellmanMap[sessionId]->_serverNonceHex,
                  _diffieHellmanMap[sessionId]->_clientNonceHex);
        } catch (const nlohmann::json::exception &e) {
          std::cerr << "JSON parsing error: " << e.what() << std::endl;
        } catch (const std::exception &e) {
          std::cerr << "An unexpected error occurred: " << e.what()
                    << std::endl;
        }
        crow::json::wvalue res;
        res["message"] = "Diffie Hellman keys setup successfully!";
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