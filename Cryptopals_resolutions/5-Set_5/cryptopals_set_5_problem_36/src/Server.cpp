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
 * @brief This method will return the production port of the server.
 *
 * This method will return the production port of the server to establish a
 * connection.
 */
const int Server::getProductionPort() const { return _portProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * This method will return the test port of the server to establish a
 * connection.
 */
const int Server::getTestPort() const { return _portTest; }
/******************************************************************************/
/**
 * @brief This method will start the endpoints that the server
 * provides to his clients
 *
 * This method will start the endpoints that the server
 * provides to his clients, namely the root endpoint and the signature
 * verification endpoint
 */
void Server::setupRoutes() { rootEndpoint(); }
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
