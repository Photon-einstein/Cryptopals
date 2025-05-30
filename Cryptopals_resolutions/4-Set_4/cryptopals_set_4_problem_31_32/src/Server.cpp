#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server() : _hmac(std::make_shared<MyCryptoLibrary::HMAC_SHA1>()) {
  std::string hexServerKey{};
  if (std::getenv("KEY_SERVER_SET_4_PROBLEM_31") != nullptr) {
    hexServerKey = std::getenv("KEY_SERVER_SET_4_PROBLEM_31");
  } else {
    const std::string errorMessage{
        "Server log | server key 'KEY_SERVER_SET_4_PROBLEM_31' must be "
        "setup prior to this call"};
    throw std::invalid_argument(errorMessage);
  }
  Server::_keyServer = MessageExtractionFacility::hexToBytes(hexServerKey);
}
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
/**
 * @brief This method is the endpoint that makes the verification of the
 * signature
 *
 * This method is the endpoint that makes the verification of the signature,
 * namely it assesses if HMAC(file) == signature
 *
 */
void Server::signatureVerificationEndpoint() {
  CROW_ROUTE(_app, "/test")
      .methods("GET"_method)([&](const crow::request &req) {
        try {
          const std::string file = req.url_params.get("file");
          std::string signature = req.url_params.get("signature");
          std::vector<unsigned char> byteMessage(file.begin(), file.end());
          std::vector<unsigned char> signatureExpectedV =
              _hmac->hmac(_keyServer, byteMessage);
          std::vector<unsigned char> signatureV =
              MessageExtractionFacility::hexToBytes(signature);

          if (insecureSignatureCompare(signatureV, signatureExpectedV)) {
            crow::json::wvalue message;
            message["file"] = file;
            message["signature"] = signature;
            message["verified"] = true;
            return crow::response(200, message);
          } else {
            crow::json::wvalue err;
            err["error"] = "Invalid signature. HMAC verification failed.";
            return crow::response(401, err);
          }
        } catch (const std::exception &e) {
          crow::json::wvalue err;
          err["error"] = e.what();
          return crow::response(500, err);
        }
      });
}
/******************************************************************************/
void Server::setupRoutes() {
  rootEndpoint();
  signatureVerificationEndpoint();
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
/**
 * @brief This method will do an insecure compare between two vector.
 *
 * This method will do an insecure compare between two vector, leaking time
 * in the process.
 *
 * @return A bool value, true if the vectors are the same, false otherwise
 */
bool Server::insecureSignatureCompare(const std::vector<unsigned char> &v1,
                                      const std::vector<unsigned char> &v2) {
  if (v1.size() != v2.size()) {
    return false;
  }
  const std::size_t size{v1.size()};
  for (std::size_t i = 0; i < size; ++i) {
    if (v1[i] != v2[i]) {
      return false;
    }
    std::this_thread::sleep_for(
        std::chrono::milliseconds(5)); // artificial timing leak
  }
  return true;
}
/******************************************************************************/