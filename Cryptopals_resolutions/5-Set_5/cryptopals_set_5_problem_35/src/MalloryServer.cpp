#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MalloryServer.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
MalloryServer::MalloryServer(const bool debugFlag, const bool testFlag)
    : _debugFlag{debugFlag}, _testFlag{testFlag} {
  _portRealServerInUse =
      (_testFlag) ? _portRealServerTest : _portRealServerProduction;
  boost::uuids::random_generator gen;
  _serverId += boost::uuids::to_string(gen());
}
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
 * @brief This method will start all the server's endpoints in a multithread
 * environment.
 *
 * This method will start all the endpoints that the server provides to their
 * clients.
 */
void MalloryServer::runServer() {
  setupRoutes();
  _app.port(_portProduction).multithreaded().run();
}
/******************************************************************************/
/**
 * @brief This method will start all the server's endpoints in a multithread
 * environment for a test scenario.
 *
 * This method will start all the endpoints that the server provides to their
 * clients, in a test scenario.
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
 * This method will clear all the sessions in memory that were created
 * after the conclusion of the Diffie Hellman key exchange protocol.
 */
void MalloryServer::clearDiffieHellmanSessionData() {
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
const int MalloryServer::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the server's test port.
 *
 * This method will return the server's test port to establish a
 * connection.
 */
const int MalloryServer::getTestPort() const { return _portTest; }
/******************************************************************************/
/**
 * @brief This method will return the g replacement strategy.
 *
 * This method will return the g replacement strategy used in this
 * attacker, in a string format.
 *
 * @return The g parameter replacement strategy used by this attacker.
 */
const std::string MalloryServer::gReplacementAttackStrategyToString(
    const gReplacementAttackStrategy &strategy) {
  switch (strategy) {
  case gReplacementAttackStrategy::NoReplacementAttack:
    return std::string("No replacement attack");
  case gReplacementAttackStrategy::gEquals1:
    return std::string("g equals 1");
  case gReplacementAttackStrategy::gEqualsP:
    return std::string("g equals p");
  case gReplacementAttackStrategy::gEqualsPminus1:
    return std::string("g equals p minus 1");
  }
  return std::string("Unknown attack strategy");
}
/******************************************************************************/

/**
 * @brief This method will start the endpoints that the server
 * provides to his clients.
 *
 * This method will start the endpoints that the server
 * provides to his clients, namely the root endpoint and the signature
 * verification endpoint.
 */
void MalloryServer::setupRoutes() {
  rootEndpoint();
  keyExchangeRoute();
  getSessionsDataEndpoint();
  messageExchangeRoute();
}
/******************************************************************************/
/**
 * @brief This method is the entry point for the server URL address.
 *
 * This method will serve as a confirmation that the server URL is up
 * and running at the root path.
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
 * key exchange protocol. The man in the middle attack is performed.
 *
 * This method runs the route that performs the Diffie Hellman
 * key exchange protocol. It receives requests and make all the calculations
 * to respond to the requests, creating a symmetric key for each connection
 * request, performing the man in the middle attack.
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
          _diffieHellmanMap[sessionId] = std::make_unique<MallorySessionData>(
              _nonceSize, extractedNonceClient, extractedClientId, _debugFlag,
              _ivLength, extractedPrimeP, extractedGeneratorG);
          _diffieHellmanMap[sessionId]->_derivedKeyHexAM =
              _diffieHellmanMap[sessionId]
                  ->_diffieHellmanAM->deriveSharedSecret(
                      extractedPublicKeyA,
                      _diffieHellmanMap[sessionId]->_serverNonceHexAM,
                      _diffieHellmanMap[sessionId]->_clientNonceHexAM);
          // generate fake client
          _diffieHellmanMap[sessionId]
              ->_fakeClientMS = std::make_unique<Client>(
              _diffieHellmanMap[sessionId]->_clientIdAM, _debugFlag,
              _diffieHellmanMap[sessionId]->_diffieHellmanAM->getPrimeP(),
              _diffieHellmanMap[sessionId]->_diffieHellmanAM->getGeneratorG());
          std::tuple<bool, std::string, std::string> serverResponse =
              _diffieHellmanMap[sessionId]
                  ->_fakeClientMS->diffieHellmanKeyExchange(
                      _portRealServerInUse);
          // extract info from response of server to fake client
          if (std::get<0>(serverResponse) == false) {
            throw std::runtime_error(
                "Mallory Server log | keyExchangeRoute(): "
                "Fake client Diffie Hellman key exchange failed");
          }
          parsedJson.clear();
          parsedJson = nlohmann::json::parse(std::get<1>(serverResponse));
          std::string sessionIdExtracted =
              parsedJson.at("sessionId").get<std::string>();
          std::string clientIdExtracted =
              parsedJson.at("clientId").get<std::string>();
          std::string clientNonceExtracted =
              parsedJson.at("clientNonce").get<std::string>();
          std::string serverNonceExtracted =
              parsedJson.at("serverNonce").get<std::string>();
          std::string messageExtracted =
              parsedJson.at("message").get<std::string>();
          // generate fake response to client
          res["message"] = messageExtracted;
          res["sessionId"] = sessionIdExtracted;
          res["diffieHellman"] = {
              {"p",
               _diffieHellmanMap[sessionId]->_diffieHellmanAM->getPrimeP()},
              {"g",
               _diffieHellmanMap[sessionId]->_diffieHellmanAM->getGeneratorG()},
              {"publicKeyB",
               _diffieHellmanMap[sessionId]->_diffieHellmanAM->getPublicKey()}};
          res["nonce"] = _diffieHellmanMap[sessionId]->_serverNonceHexAM;
          // confirmation payload
          nlohmann::json confirmationPayload = {
              {"sessionId", sessionIdExtracted},
              {"clientId", extractedClientId},
              {"clientNonce", _diffieHellmanMap[sessionId]->_clientNonceHexAM},
              {"serverNonce", _diffieHellmanMap[sessionId]->_serverNonceHexAM},
              {"message", messageExtracted}};
          const std::string confirmationString = confirmationPayload.dump();
          std::string encryptedConfirmationHex =
              EncryptionUtility::encryptMessageAes256CbcMode(
                  confirmationString,
                  _diffieHellmanMap[sessionId]
                      ->_diffieHellmanAM->getSymmetricKey(),
                  _diffieHellmanMap[sessionId]->_ivAM);
          res["confirmation"] = {
              {"ciphertext", encryptedConfirmationHex},
              {"iv", MessageExtractionFacility::toHexString(
                         _diffieHellmanMap[sessionId]->_ivAM)}};
          // save session id with real server to future use
          _diffieHellmanMap[sessionId]->_sessionIdMS = sessionIdExtracted;
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Mallory Server log | JSON parsing error: ") +
              e.what();
          return crow::response(404, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string(
                  "Mallory Server log | An unexpected error occurred: ") +
              e.what();
          return crow::response(400, err);
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method runs the route that performs the message exchange using
 * symmetric encryption after the Diffie Hellman key exchange protocol has
 * been completed. The man in the middle attack is performed.
 *
 * This method runs the route that performs the message exchange using
 * symmetric encryption after the Diffie Hellman key exchange protocol has
 * been completed. This fake server performs the man in the middle attack.
 * Normal function from a normal server is to receive messages from clients,
 * checks the validity of the session id and if valid, sends back a confirmation
 * response. This fake server decrypt, read and encrypt again with another
 * session to the real server.
 *
 * @throws std::runtime_error if there is an error in messageExchangeRoute.
 */
void MalloryServer::messageExchangeRoute() {
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
          // check if session id already exists
          std::lock_guard<std::mutex> lock(_diffieHellmanMapMutex);
          boost::uuids::uuid sessionIdASFound;
          bool sessionIdASFoundFlag{false};
          // search real session id (M -> S)
          for (const auto &pair : _diffieHellmanMap) {
            if (pair.second->_sessionIdMS == extractedSessionId) {
              sessionIdASFoundFlag = true;
              sessionIdASFound = pair.first;
            }
          }
          if (!sessionIdASFoundFlag) {
            throw std::runtime_error(
                "Mallory Server log | MessageExchangeRoute(): "
                "Session id: " +
                extractedSessionId + " not found from Alice -> Mallory");
          }
          // convert iv to bytes and store it
          _diffieHellmanMap[sessionIdASFound]->_ivAM =
              MessageExtractionFacility::hexToBytes(extractedIv);
          const std::string plaintext =
              EncryptionUtility::decryptMessageAes256CbcMode(
                  extractedCiphertext,
                  _diffieHellmanMap[sessionIdASFound]
                      ->_diffieHellmanAM->getSymmetricKey(),
                  _diffieHellmanMap[sessionIdASFound]->_ivAM);
          if (_debugFlag) {
            std::cout << "Mallory Server log | MessageExchangeRoute() - "
                         "decrypted plaintext: "
                      << plaintext << std::endl;
          }
          // build fake client request to the real server
          // rotate iv
          _diffieHellmanMap[sessionIdASFound]
              ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
              ->_iv = EncryptionUtility::generateRandomIV(_ivLength);
          // calculate ciphertext
          const std::string ciphertextMS =
              EncryptionUtility::encryptMessageAes256CbcMode(
                  plaintext,
                  _diffieHellmanMap[sessionIdASFound]
                      ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
                      ->_diffieHellman->getSymmetricKey(),
                  _diffieHellmanMap[sessionIdASFound]
                      ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
                      ->_iv);
          // built body request MS
          std::string requestBodyMS = fmt::format(
              R"({{
            "messageType": "client_message_exchange",
            "protocolVersion": "1.0",
            "sessionId": "{}",
            "iv": "{}",
            "ciphertext": "{}"
          }})",
              extractedSessionId,
              MessageExtractionFacility::toHexString(
                  _diffieHellmanMap[sessionIdASFound]
                      ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
                      ->_iv),
              ciphertextMS);
          cpr::Response responseMS =
              cpr::Post(cpr::Url{std::string("http://localhost:") +
                                 std::to_string(_portRealServerInUse) +
                                 std::string("/messageExchange")},
                        cpr::Header{{"Content-Type", "application/json"}},
                        cpr::Body{requestBodyMS});
          if (responseMS.status_code != 201) {
            throw std::runtime_error(
                "Mallory Server log | messageExchange(): "
                "Message exchange failed at fake client ID: " +
                _diffieHellmanMap[sessionIdASFound]
                    ->_fakeClientMS->getClientId());
          }
          if (_debugFlag) {
            Client::printServerResponse(responseMS);
          }
          nlohmann::json parsedJsonMS = nlohmann::json::parse(responseMS.text);
          const std::string extractedSessionIdMS =
              parsedJsonMS.at("sessionId").get<std::string>();
          if (extractedSessionIdMS != extractedSessionId) {
            throw std::runtime_error(
                "Mallory Server log | messageExchange(): "
                "Message exchange failed at client ID: " +
                _diffieHellmanMap[sessionIdASFound]
                    ->_fakeClientMS->getClientId() +
                " session ID send and received don't match.");
          }
          const std::string extractedCiphertextMS =
              parsedJsonMS.at("confirmation")
                  .at("ciphertext")
                  .get<std::string>();
          const std::string extractedIvHexMS =
              parsedJsonMS.at("confirmation").at("iv").get<std::string>();
          // update iv MS
          _diffieHellmanMap[sessionIdASFound]
              ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
              ->_iv = MessageExtractionFacility::hexToBytes(extractedIvHexMS);
          // decrypt received ciphertext MS
          const std::string decryptedCiphertextMS =
              EncryptionUtility::decryptMessageAes256CbcMode(
                  extractedCiphertextMS,
                  _diffieHellmanMap[sessionIdASFound]
                      ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
                      ->_diffieHellman->getSymmetricKey(),
                  _diffieHellmanMap[sessionIdASFound]
                      ->_fakeClientMS->getDiffieHellmanMap()[extractedSessionId]
                      ->_iv);
          // rotate iv AM
          _diffieHellmanMap[sessionIdASFound]->_ivAM =
              EncryptionUtility::generateRandomIV(_ivLength);
          // encrypt server's confirmation message
          std::string serverConfirmationMessageEncryptedAM =
              EncryptionUtility::encryptMessageAes256CbcMode(
                  decryptedCiphertextMS,
                  _diffieHellmanMap[sessionIdASFound]
                      ->_diffieHellmanAM->getSymmetricKey(),
                  _diffieHellmanMap[sessionIdASFound]->_ivAM);
          // build confirmation response
          res["sessionId"] = extractedSessionId;
          res["confirmation"] = {
              {"ciphertext", serverConfirmationMessageEncryptedAM},
              {"iv", MessageExtractionFacility::toHexString(
                         _diffieHellmanMap[sessionIdASFound]->_ivAM)}};
        } catch (const nlohmann::json::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string("Mallory Server log | JSON parsing error: ") +
              e.what();
          return crow::response(404, err);
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["message"] =
              std::string(
                  "Mallory Server log | An unexpected error occurred: ") +
              e.what();
          return crow::response(400, err);
        }
        return crow::response(201, res);
      });
}
/******************************************************************************/
/**
 * @brief This method runs the route that gets all the current available
 * fake sessions created using the Diffie Hellman key exchange protocol, after
 * the man in the middle attack is performed.
 *
 * This method runs the route that gets all the current available sessions
 * created using the Diffie Hellman key exchange protocol, after
 * the man in the middle attack is performed.
 * It outputs all the session data in json format.
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
            const std::string realSessionId =
                _diffieHellmanMap[sessionId]->_sessionIdMS;
            res[realSessionId] = {
                {"sessionId", realSessionId},
                {"clientId", sessionData->_clientIdAM},
                {"clientNonce", sessionData->_clientNonceHexAM},
                {"serverNonce", sessionData->_serverNonceHexAM},
                {"derivedKey", sessionData->_derivedKeyHexAM},
                {"iv",
                 MessageExtractionFacility::toHexString(sessionData->_ivAM)}};
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
 * @brief This method will generate an unique session's id.
 *
 * This method will generate an unique session's id for a given connection
 * request.
 *
 * @return An unique session's ID to be used.
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
