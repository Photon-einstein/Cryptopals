#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MalloryServer.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
MalloryServer::MalloryServer(const bool debugFlag) : _debugFlag{debugFlag} {}
/******************************************************************************/
MalloryServer::~MalloryServer() {
  // server graceful stop
  _app.stop();
  if (_serverThread.joinable()) {
    _serverThread.join(); // Wait for thread to finish
  }
  clearDiffieHellmanSessionData();
}
/******************************************************************************/
/**
 * @brief This method will start all the server endpoints in a multi thread
 * environment
 *
 * This method will start all the endpoints that the server provides to their
 * clients
 */
void MalloryServer::runServer() {
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
void MalloryServer::runServerTest() {
  _serverThread = std::thread([this]() {
    setupRoutes();
    _app.port(_portTest).multithreaded().run();
  }); // Let it live until process ends
}
/******************************************************************************/
/**
 * @brief This method will clear all the sessions in memory.
 *
 * This method will clear all the sessions in memory that were created executing
 * the Diffie Hellman key exchange protocol.
 */
void MalloryServer::clearDiffieHellmanSessionData() {
  std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
  _diffieHellmanMap.clear();
}
/******************************************************************************/
/**
 * @brief This method will return the production port of the server.
 *
 * This method will return the production port of the server to establish a
 * connection.
 */
const int MalloryServer::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * This method will return the test port of the server to establish a
 * connection.
 */
const int MalloryServer::getTestPort() const { return _portTest; }
/******************************************************************************/
/**
 * @brief This method will start the endpoints that the server
 * provides to his clients
 *
 * This method will start the endpoints that the server
 * provides to his clients, namely the root endpoint and the signature
 * verification endpoint
 */
void MalloryServer::setupRoutes() {
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
void MalloryServer::rootEndpoint() {
  CROW_ROUTE(_app, "/").methods("GET"_method)([&]() {
    crow::json::wvalue rootMessage;
    rootMessage["message"] = std::string(
        "Mallory Server log | Root endpoint, server up and running");
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
void MalloryServer::keyExchangeRoute() {
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
          _diffieHellmanMap[sessionId] = std::make_unique<MallorySessionData>(
              _nonceSize, extractedNonceClient, extractedClientId, _debugFlag,
              _ivLength);

          _diffieHellmanMap[sessionId]->_AMderivedKeyHex =
              _diffieHellmanMap[sessionId]
                  ->_AMdiffieHellman->deriveSharedSecret(
                      extractedPublicKeyA,
                      _diffieHellmanMap[sessionId]->_AMserverNonceHex,
                      _diffieHellmanMap[sessionId]->_AMclientNonceHex);
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Mallory Server log | JSON parsing error: ") +
              e.what();
          return crow::response(400, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string(
                  "Mallory Server log | An unexpected error occurred: ") +
              e.what();
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method runs the route that gets all the current available
 * sessions created using the Diffie Hellman key exchange protocol.
 *
 * This method runs the route that gets all the current available sessions
 * created using the Diffie Hellman key exchange protocol. It outputs all the
 * session data in json format.
 */
void MalloryServer::getSessionsDataEndpoint() {
  CROW_ROUTE(_app, "/sessionsData")
      .methods("GET"_method)([&](const crow::request &req) {
        try {
          crow::json::wvalue res;
          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          for (const auto &entry : _diffieHellmanMap) {
            const auto &sessionId = entry.first;
            const auto &sessionData = entry.second;
            std::string sessionIdStr = boost::uuids::to_string(sessionId);
            res[sessionIdStr] = {
                {"sessionId (Alice to Mallory)", sessionIdStr},
                {"clientId (Alice to Mallory)", sessionData->_AMclientId},
                {"clientNonce (Alice to Mallory)",
                 sessionData->_AMclientNonceHex},
                {"serverNonce (Alice to Mallory)",
                 sessionData->_AMserverNonceHex},
                {"derivedKey (Alice to Mallory)",
                 sessionData->_AMderivedKeyHex},
                {"iv (Alice to Mallory)",
                 MessageExtractionFacility::toHexString(sessionData->_AMiv)}};
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
 *
 * @return A unique session ID to be used.
 */
boost::uuids::uuid MalloryServer::generateUniqueSessionId() {
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
