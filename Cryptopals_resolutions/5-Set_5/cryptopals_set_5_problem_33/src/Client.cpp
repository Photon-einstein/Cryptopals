#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
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
  try {
    if (response.status_code != 201) {
      throw std::runtime_error("Diffie Hellman key exchange failed");
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    _sessionId = parsedJson.at("sessionId").get<std::string>();
    _extractedNonceServer = parsedJson.at("nonce").get<std::string>();
    std::string extractedGroupName =
        parsedJson.at("diffieHellman").at("groupName").get<std::string>();
    std::string extractedPublicKeyB =
        parsedJson.at("diffieHellman").at("publicKeyB").get<std::string>();
    if (_debugFlag) {
      std::cout << "\n--- Extracted Data ---" << std::endl;
      std::cout << "Session id: " << _sessionId << std::endl;
      std::cout << "Nonce: " << _extractedNonceServer << std::endl;
      std::cout << "Group Name: " << extractedGroupName << std::endl;
      std::cout << "Public Key B: " << extractedPublicKeyB << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    MessageExtractionFacility::UniqueBIGNUM peerPublicKey =
        MessageExtractionFacility::hexToUniqueBIGNUM(extractedPublicKeyB);
    _derivedKeyHex = _diffieHellman->deriveSharedSecret(
        extractedPublicKeyB, _extractedNonceServer, _clientNonceHex);
  } catch (const std::exception &e) {
    std::cerr << "Client log | secret key derivation step: " << e.what()
              << std::endl;
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
