#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag) : _debugFlag(debugFlag), _hmac(std::make_shared<MyCryptoLibrary::HMAC_SHA1>()) {
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
}
/******************************************************************************/
/**
 * @brief This method will validate if a given message produces the
 * given message authentication code (MAC)
 *
 * This method will validate if a given message produces the
 * given message authentication code (MAC), it will perform the following
 * test: MD4(private server key || msg) == mac
 *
 * @param msg The message to be authenticated
 * @param mac The message authentication code (mac) to be validated in
 * binary format
 *
 * @return A bool value, true if the mac received matches the
 * mac produced by the server, false otherwise
 */
bool Server::validateMac(const std::vector<unsigned char> &msg,
                         const std::vector<unsigned char> &mac) {
  return true;
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
 * @brief This method is the endpoint that makes the verification of the signature
 *
 * This method is the endpoint that makes the verification of the signature, namely
 * it assesses if HMAC(file) == signature
 * 
 */    
void Server::signatureVerificationEndpoint() {
  CROW_ROUTE(_app, "/test").methods("GET"_method) ([&](const crow::request& req){
    try{
      const std::string file = req.url_params.get("file");
      std::string signature = req.url_params.get("signature");
      std::vector<unsigned char> byteMessage(file.begin(), file.end());
      std::vector<unsigned char> signatureExpected = _hmac->hmac(_keyServer, byteMessage);
      const std::string signatureExpectedS = MessageExtractionFacility::toHexString(signatureExpected);
      std::cout<<"Signature expected: "<<signatureExpectedS<<std::endl;
      crow::json::wvalue message;
       if (signature.substr(0, 2) != "0x") {
        signature = "0x" + signature;
      }
      message["file"] = file;
      message["signature"] = signature;
      message["serverTest"] = (signature == signatureExpectedS);
      return crow::response(200, message);
    }
    catch (const std::exception& e) {
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
  std::thread([this]() {
    setupRoutes();
    _app.port(_portTest).multithreaded().run();
  }).detach(); // Let it live until process ends
}
/******************************************************************************/
