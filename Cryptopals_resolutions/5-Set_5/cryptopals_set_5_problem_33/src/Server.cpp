#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MessageExtractionFacility.hpp"
#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server() {
  std::map<std::string, DHParametersLoader::DHParameters> dhParametersMap =
      DHParametersLoader::loadDhParameters(_dhParametersFilename);
  if (dhParametersMap.find("cryptopals-group-33-small") !=
      dhParametersMap.end()) {
    std::cout << "Group name: "
              << dhParametersMap["cryptopals-group-33-small"].groupName
              << std::endl;
    std::cout << "p(hex): " << dhParametersMap["cryptopals-group-33-small"].pHex
              << std::endl;
    std::cout << "g(hex): " << dhParametersMap["cryptopals-group-33-small"].gHex
              << std::endl;
    std::cout << "description: "
              << dhParametersMap["cryptopals-group-33-small"].description
              << std::endl;
    std::cout << "notes: " << dhParametersMap["cryptopals-group-33-small"].notes
              << "\n"
              << std::endl;
    _dhParameter = dhParametersMap["cryptopals-group-33-small"];
    MessageExtractionFacility::UniqueBIGNUM pBN =
        MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter.pHex);
    std::string p = MessageExtractionFacility::BIGNUMToDec(pBN.get());
    std::cout << "p (BN decimal) = " << p << std::endl;
  }
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
void Server::setupRoutes() { rootEndpoint(); }
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
