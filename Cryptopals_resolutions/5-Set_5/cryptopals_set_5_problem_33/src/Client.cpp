#include "crow.h"
#include <chrono>
#include <fmt/core.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include "./../include/Client.hpp"

/* constructor / destructor */
Client::Client(const bool debugFlag)
    : _debugFlag{debugFlag},
      _diffieHellman(std::make_unique<MyCryptoLibrary::Diffie_Hellman>()),
      _clientNonceHex{
          MessageExtractionFacility::generateCryptographicNonce(_nonceSize)} {
  if (_debugFlag) {
    std::cout << "Client log | Nonce (hex): " << _clientNonceHex << "\n"
              << std::endl;
  }
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
void Client::diffieHellmanKeyExchange() {
  std::string requestBody =
      fmt::format(R"({{
    "messageType": "client_hello",
    "protocolVersion": "1.0",
    "clientId": "{}",
    "nonce": "{}",
    "diffieHellman": {{
        "groupName": "{}",
        "publicKeyA": "{}"
    }}
}})",
                  _clientId, _clientNonceHex, _diffieHellman->getGroupName(),
                  _diffieHellman->getPublicKey());
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_portServerProduction) +
                         std::string("/keyExchange")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  if (_debugFlag) {
    printServerResponse(response);
  }
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
  std::cout << "Body:\n";
  if (response.text.empty()) {
    std::cout << "[Empty Body]\n";
  } else {
    try {
      nlohmann::json parsedJson = nlohmann::json::parse(response.text);
      std::cout << parsedJson.dump(2) << "\n"; // '2' for 2-space indentation
    } catch (const nlohmann::json::exception &e) {
      // Not valid JSON, print as raw text
      std::cout << response.text << "\n";
      std::cerr << "Warning: Body is not valid JSON, printing raw. Error: "
                << e.what() << "\n";
    }
  }
}
/******************************************************************************/
