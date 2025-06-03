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
#include "./../include/EncryptionUtility.hpp"

/* constructor / destructor */
Client::Client(const std::string &clientId, const bool debugFlag)
    : _clientId{clientId}, _debugFlag{debugFlag} {}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
/**
 * @brief This method will perform the Diffie Hellman key exchange protocol with
 * a given server.
 *
 * This method will perform the Diffie Hellman key exchange protocol with
 * a given server, in order to agree on a given symmetric encryption key.
 */
void Client::diffieHellmanKeyExchange() {
  std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman(
      std::make_unique<MyCryptoLibrary::DiffieHellman>(_debugFlag));
  std::string clientNonceHex{
      EncryptionUtility::generateCryptographicNonce(_nonceSize)};
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
                  _clientId, clientNonceHex, diffieHellman->getGroupName(),
                  diffieHellman->getPublicKey());
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_portServerProduction) +
                         std::string("/keyExchange")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  try {
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | diffieHellmanKeyExchange(): "
                               "Diffie Hellman key exchange failed");
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    std::string sessionId = parsedJson.at("sessionId").get<std::string>();
    std::string extractedNonceServer =
        parsedJson.at("nonce").get<std::string>();
    std::string extractedGroupName =
        parsedJson.at("diffieHellman").at("groupName").get<std::string>();
    std::string extractedPublicKeyB =
        parsedJson.at("diffieHellman").at("publicKeyB").get<std::string>();
    std::string ciphertext =
        parsedJson.at("confirmation").at("ciphertext").get<std::string>();
    std::string ivHex =
        parsedJson.at("confirmation").at("iv").get<std::string>();
    std::vector<uint8_t> iv = MessageExtractionFacility::hexToBytes(ivHex);
    if (_debugFlag) {
      std::cout << "\n--- Client log | Extracted Data ---" << std::endl;
      std::cout << "\tSession id: " << sessionId << std::endl;
      std::cout << "\tNonce: " << extractedNonceServer << std::endl;
      std::cout << "\tGroup Name: " << extractedGroupName << std::endl;
      std::cout << "\tPublic Key B: " << extractedPublicKeyB << std::endl;
      std::cout << "\tCiphertext: " << ciphertext << std::endl;
      std::cout << "\tIV(hex): " << ivHex << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    _diffieHellmanMap[sessionId] = std::make_unique<SessionData>(
        std::move(diffieHellman), extractedNonceServer, clientNonceHex, iv);
    _diffieHellmanMap[sessionId]->_derivedKeyHex =
        _diffieHellmanMap[sessionId]->_diffieHellman->deriveSharedSecret(
            extractedPublicKeyB, _diffieHellmanMap[sessionId]->_serverNonceHex,
            _diffieHellmanMap[sessionId]->_clientNonceHex);
    // confirmation of the data received
    std::tuple<bool, std::string> connectionTestResult =
        confirmationServerResponse(
            ciphertext,
            MessageExtractionFacility::hexToBytes(
                _diffieHellmanMap[sessionId]->_derivedKeyHex),
            _diffieHellmanMap[sessionId]->_iv, sessionId, _clientId,
            _diffieHellmanMap[sessionId]->_clientNonceHex,
            _diffieHellmanMap[sessionId]->_serverNonceHex,
            _diffieHellmanMap[sessionId]
                ->_diffieHellman->getConfirmationMessage());
    if (std::get<0>(connectionTestResult) == false) {
      throw std::runtime_error("Client log | diffieHellmanKeyExchange(): "
                               "Diffie Hellman key exchange failed");
    } else {
      std::cout << "\n\n-------------------------------------------------------"
                   "----------------------"
                << std::endl;
      std::cout << "Client log | diffieHellmanKeyExchange(): Diffie Hellman "
                   "key exchange succeed"
                << std::endl;
      try {
        const std::string &decrypted = std::get<1>(connectionTestResult);
        nlohmann::json parsed = nlohmann::json::parse(decrypted);
        std::cout << "Ciphertext decrypted:\n" << parsed.dump(4) << std::endl;
      } catch (const nlohmann::json::exception &e) {
        std::cerr << "\tWarning: Decrypted ciphertext is not valid JSON, "
                     "printing raw. Error: "
                  << e.what() << std::endl;
        std::cout << "\tCiphertext decrypted (raw): "
                  << std::get<1>(connectionTestResult) << std::endl;
      }
      std::cout << "-----------------------------------------------------------"
                   "------------------\n"
                << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Client log | diffieHellmanKeyExchange(): secret key "
                 "derivation step: "
              << e.what() << std::endl;
  }
}
/******************************************************************************/
/**
 * @brief This method will print the server response to the Diffie Hellman
 * key exchange protocol.
 *
 * This method will print the server response to the Diffie Hellman
 * key exchange protocol. The response is a json text, and it will be printed
 * in a structured way.
 *
 * @param response The response received by the server during the execution of
 * the Diffie Hellman key exchange protocol.
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
std::tuple<bool, std::string> Client::confirmationServerResponse(
    const std::string &ciphertext, const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv, const std::string &sessionId,
    const std::string &clientId, const std::string &clientNonce,
    const std::string &serverNonce, const std::string &message) {
  bool comparisonRes{false};
  std::string plaintext;
  try {
    plaintext =
        EncryptionUtility::decryptMessageAes256CbcMode(ciphertext, key, iv);
    nlohmann::json parsedJson = nlohmann::json::parse(plaintext);
    std::string sessionIdExtracted =
        parsedJson.at("sessionId").get<std::string>();
    std::string clientIdExtracted =
        parsedJson.at("clientId").get<std::string>();
    std::string clientNonceExtracted =
        parsedJson.at("clientNonce").get<std::string>();
    std::string serverNonceExtracted =
        parsedJson.at("serverNonce").get<std::string>();
    std::string messageExtracted = parsedJson.at("message").get<std::string>();
    if (sessionId == sessionIdExtracted && clientId == clientIdExtracted &&
        clientNonce == clientNonceExtracted &&
        serverNonce == serverNonceExtracted && message == messageExtracted) {
      comparisonRes = true;
    }
  } catch (const std::exception &e) {
    std::cerr << "Client log | confirmationServerResponse(): " << e.what()
              << std::endl;
    return std::make_tuple(comparisonRes, plaintext);
  }
  return std::make_tuple(comparisonRes, plaintext);
}
/******************************************************************************/