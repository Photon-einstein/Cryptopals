#include "crow.h"
#include <chrono>
#include <iostream>
#include <openssl/rand.h>

#include "./../include/Client.hpp"

/* constructor / destructor */
Client::Client()
    : _diffieHellman(std::make_unique<MyCryptoLibrary::Diffie_Hellman>()),
      _clientNonceHex{
          MessageExtractionFacility::generateCryptographicNonce(_nonceSize)} {
  std::cout << "Client log | Nonce (hex): " << _clientNonceHex << "\n"
            << std::endl;
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
void Client::diffieHellmanKeyExchange() {
  std::string requestBody = R"({})";
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_portServerProduction) +
                         std::string("/keyExchange")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  printServerResponse(response);
}
/******************************************************************************/
/**
 * @brief This method will print in a structured way the server response
 *
 * This method will print in a structured way the server response to a client
 * curl request.
 */
void Client::printServerResponse(const cpr::Response &response) {
  std::cout << "Status Code: " << response.status_code << "\n";
  std::cout << "Headers:\n";
  for (const auto &header : response.header) {
    std::cout << header.first << ": " << header.second << "\n";
  }
  std::cout << "Body:\n" << response.text << "\n";
}
/******************************************************************************/
