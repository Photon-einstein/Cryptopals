#include "crow.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <fmt/core.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <string_view>

#include "./../include/Client.hpp"
#include "./../include/EncryptionUtility.hpp"

/* constructor / destructor */
Client::Client(const std::string &clientId, const bool debugFlag,
               const std::string &groupNameDH)
    : _clientId{clientId}, _debugFlag{debugFlag}, _groupNameDH{groupNameDH} {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null");
  } else if (_groupNameDH.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Group name is null");
  }
}
/******************************************************************************/
Client::Client(const std::string &clientId, const bool debugFlag,
               const std::string &groupNameDH, const bool parameterInjection)
    : _clientId{clientId}, _debugFlag{debugFlag}, _groupNameDH{groupNameDH},
      _parameterInjection{parameterInjection} {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null");
  } else if (_groupNameDH.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Group name is null");
  }
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
/**
 * @brief This method will perform the Diffie Hellman key exchange protocol
 * with a given server.
 *
 * This method will perform the Diffie Hellman key exchange protocol with
 * a given server, in order to agree on a given symmetric encryption key.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 *
 * @return A tuple containing:
 *         - bool: indicating success or failure of validation.
 *         - std::string: the decrypted plaintext message. If decryption
 * fails, this may contain garbage or incomplete data.
 *         - std::string: the created session ID
 * @throw runtime_error if portServerNumber < 1024
 */
const std::tuple<bool, std::string, std::string>
Client::diffieHellmanKeyExchange(const int portServerNumber) {
  if (portServerNumber < 1023) {
    throw std::runtime_error(
        "Client log | diffieHellmanKeyExchange(): "
        "Invalid port server number used, should be greater than 1023.");
  }
  std::tuple<bool, std::string, std::string> connectionTestResult;
  std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman(
      std::make_unique<MyCryptoLibrary::DiffieHellman>(
          _debugFlag, _parameterInjection, _groupNameDH));
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
                  getClientId(), clientNonceHex, diffieHellman->getGroupName(),
                  diffieHellman->getPublicKey());
  cpr::Response response = cpr::Post(
      cpr::Url{std::string("http://localhost:") +
               std::to_string(portServerNumber) + std::string("/keyExchange")},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{requestBody});
  try {
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | diffieHellmanKeyExchange(): "
                               "Diffie Hellman key exchange failed");
    }
    if (_debugFlag) {
      printServerResponse(response);
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
    connectionTestResult = confirmationServerResponse(
        ciphertext,
        MessageExtractionFacility::hexToBytes(
            _diffieHellmanMap[sessionId]->_derivedKeyHex),
        _diffieHellmanMap[sessionId]->_iv, sessionId, getClientId(),
        _diffieHellmanMap[sessionId]->_clientNonceHex,
        _diffieHellmanMap[sessionId]->_serverNonceHex,
        _diffieHellmanMap[sessionId]->_diffieHellman->getConfirmationMessage());
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
    std::cerr << e.what() << std::endl;
  }
  return connectionTestResult;
}
/******************************************************************************/
/**
 * @brief This method will perform the message exchange route.
 *
 * This method will perform a secure message exchange a with a given server
 * after the Diffie Hellman key exchange protocol has been successfully executed
 * and a valid session created.
 *
 * @param portServerNumber The number of the server to use in this message
 * exchange.
 * @param sessionId The session id to be used in this connection with the
 * server.
 *
 * @return A bool, true if the exchange and validation was successful, failure
 * otherwise.
 *
 * @throw runtime_error if there was an error in the messageExchange.
 */
const bool Client::messageExchange(const int portServerNumber,
                                   const std::string &sessionId) {
  bool connectionTestResult{false};
  try {
    if (portServerNumber < 1023) {
      throw std::runtime_error(
          "Client log | messageExchange(): "
          "Invalid port server number used, should be greater than 1023.");
    }
    if (_diffieHellmanMap.empty()) {
      throw std::runtime_error("Client log | messageExchange(): "
                               "No sessions are set on the client side, not "
                               "ready to run this route.");
    }
    if (_diffieHellmanMap.find(sessionId) == _diffieHellmanMap.end()) {
      throw std::runtime_error(
          "Client log | messageExchange(): "
          "The session id received as an argument is not setup.");
    }
    // rotate iv
    _diffieHellmanMap[sessionId]->_iv =
        EncryptionUtility::generateRandomIV(_ivLength);
    // confirmation message
    const std::string clientMessageSent =
        std::string("Hello from client ID: ") + _clientId +
        " at session ID: " + sessionId + " at " +
        EncryptionUtility::getFormattedTimestamp() + ".";
    // calculate ciphertext
    const std::string ciphertext =
        EncryptionUtility::encryptMessageAes256CbcMode(
            clientMessageSent,
            _diffieHellmanMap[sessionId]->_diffieHellman->getSymmetricKey(),
            _diffieHellmanMap[sessionId]->_iv);
    // built body request
    std::string requestBody =
        fmt::format(R"({{
      "messageType": "client_message_exchange",
      "protocolVersion": "1.0",
      "sessionId": "{}",
      "iv": "{}",
      "ciphertext": "{}"
    }})",
                    sessionId,
                    MessageExtractionFacility::toHexString(
                        _diffieHellmanMap[sessionId]->_iv),
                    ciphertext);
    cpr::Response response =
        cpr::Post(cpr::Url{std::string("http://localhost:") +
                           std::to_string(portServerNumber) +
                           std::string("/messageExchange")},
                  cpr::Header{{"Content-Type", "application/json"}},
                  cpr::Body{requestBody});
    if (_debugFlag) {
      printServerResponse(response);
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    const std::string extractedSessionId =
        parsedJson.at("sessionId").get<std::string>();
    if (extractedSessionId != sessionId) {
      throw std::runtime_error("Client log | messageExchange(): "
                               "Message exchange failed at client ID: " +
                               _clientId +
                               " session ID send and received don't match.");
    }
    const std::string extractedCiphertext =
        parsedJson.at("confirmation").at("ciphertext").get<std::string>();
    const std::string extractedIvHex =
        parsedJson.at("confirmation").at("iv").get<std::string>();
    // update iv
    _diffieHellmanMap[sessionId]->_iv =
        MessageExtractionFacility::hexToBytes(extractedIvHex);
    // decrypt received ciphertext
    const std::string decryptedCiphertext =
        EncryptionUtility::decryptMessageAes256CbcMode(
            extractedCiphertext,
            _diffieHellmanMap[extractedSessionId]
                ->_diffieHellman->getSymmetricKey(),
            _diffieHellmanMap[extractedSessionId]->_iv);
    // check return values
    if (decryptedCiphertext.find(clientMessageSent) != std::string::npos) {
      connectionTestResult = true;
      if (_debugFlag) {
        std::cout << "Client log | messageExchange(): decrypted message "
                     "received from the server: \n'"
                  << decryptedCiphertext << "'." << std::endl;
      }
    } else {
      throw std::runtime_error(
          "Client log | messageExchange(): "
          "Message exchange failed at client ID: " +
          _clientId +
          " message received doesn't contain data from message sent,"
          " message received: " +
          decryptedCiphertext);
    }
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return connectionTestResult;
}
/******************************************************************************/
/**
 * @brief This method will confirm if a given session id is correctly setup.
 *
 * This method will confirm if a given session id is correctly setup on the
 * client side.
 *
 * @return A bool value, true if the sessionId exists, false otherwise.
 */
bool Client::confirmSessionId(const std::string &sessionId) {
  return _diffieHellmanMap.find(sessionId) != _diffieHellmanMap.end();
}
/******************************************************************************/
/**
 * @brief This method sets the server's test port to a new one.
 *
 * This method sets the server's test port to a new one, used only for
 * test purposes.
 *
 * @throw runtime_error if the portServerTest is not a valid one.
 */
void Client::setTestPort(const int portServerTest) {
  if (portServerTest < 1024 || portServerTest > 49151) {
    throw std::runtime_error(
        "Client log | setTestPort(): "
        "invalid port test number given, must be in range [1024, 49151]");
  }
  _portServerTest = portServerTest;
}
/******************************************************************************/

/**
 * @brief This method returns the client ID.
 *
 * This method returns the client ID of a given client.
 *
 * @return A string, the client ID.
 * @throw runtime_error if the client ID is null.
 */
const std::string &Client::getClientId() const {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null");
  }
  return _clientId;
}
/******************************************************************************/
/**
 * @brief This method will return the server's production port.
 *
 * This method will return the server's production port to establish a
 * connection.
 *
 * @return An int, the server's production port.
 */
const int Client::getProductionPort() const { return _portServerProduction; }
/******************************************************************************/
/**
 * @brief This method will return the server's test port.
 *
 * This method will return the server's test port to establish a
 * connection.
 *
 * @return An int, the server test port.
 */
const int Client::getTestPort() const { return _portServerTest; }
/******************************************************************************/
/**
 * @brief This method will return the Diffie Hellman's map.
 *
 * This method will return the Diffie Hellman's map of the client.
 *
 * @return A map, the client's DH map.
 */
std::map<std::string, std::unique_ptr<SessionData>> &
Client::getDiffieHellmanMap() {
  return _diffieHellmanMap;
}
/******************************************************************************/
/**
 * @brief This method does the verification if this entry exists on the client
 * side.
 *
 * This method verify if this entry exists on the client side.
 * These method's arguments are one entry from the endpoint of the server
 * named GET '/sessionsData'.
 *
 * @return Bool value, true if there is a match, false otherwise.
 */
const bool Client::verifyServerSessionDataEntryEndpoint(
    const std::string &sessionId, const std::string &clientId,
    const std::string &clientNonce, const std::string &serverNonce,
    const std::string &derivedKey, const std::string &iv) const {
  if (_diffieHellmanMap.find(sessionId) == _diffieHellmanMap.end() ||
      _clientId != clientId ||
      _diffieHellmanMap.at(sessionId)->_clientNonceHex != clientNonce ||
      _diffieHellmanMap.at(sessionId)->_serverNonceHex != serverNonce ||
      _diffieHellmanMap.at(sessionId)->_derivedKeyHex != derivedKey ||
      MessageExtractionFacility::toHexString(
          _diffieHellmanMap.at(sessionId)->_iv) != iv) {
    return false;
  }
  return true;
}
/******************************************************************************/
/**
 * @brief This method will print the server response to the Diffie Hellman
 * key exchange protocol.
 *
 * This method will print the server response to the Diffie Hellman key exchange
 * protocol. The response is a json text, and it will be printed in a structured
 * way.
 *
 * @param response The response sent by the server during the execution
 * of the Diffie Hellman key exchange protocol.
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
/**
 * @brief This method will perform the decryption of the ciphertext received
 * by the server and test it against the plaintext data received.
 *
 * This method will perform the decryption of the ciphertext received by
 * the server and test it against the plaintext data received. The test passes
 * if the data matches for every fields.
 *
 * @param ciphertext The ciphertext send by the server as the challenge to
 * check if the Diffie Hellman key exchange protocol was executed successfully
 * by the client.
 * @param key The symmetric key derived by the client in raw bytes, after the
 * conclusion of the Diffie Hellman key exchange protocol.
 * @param iv The initialization vector of the AES-256-CBC mode encryption
 * process, sent by the server, in raw bytes.
 * @param sessionId The unique session ID sent by the server.
 * @param clientId The client ID associated with this connection.
 * @param clientNonce The client nonce associated with this connection, in
 * hexadecimal format.
 * @param serverNonce The server nonce associated with this connection, in
 * hexadecimal format.
 * @param message The conclusion message expected from this protocol starts
 * with the expected message (e.g. "Key exchange complete").
 *
 * @return A tuple containing:
 *         - bool: indicating success or failure of validation.
 *         - std::string: the decrypted plaintext message. If decryption
 * fails, this may contain garbage or incomplete data.
 */
std::tuple<bool, std::string, std::string> Client::confirmationServerResponse(
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
        serverNonce == serverNonceExtracted &&
        messageExtracted.starts_with(message)) {
      comparisonRes = true;
    }
  } catch (const std::exception &e) {
    std::cerr << "Client log | confirmationServerResponse(): " << e.what()
              << std::endl;
    return std::make_tuple(comparisonRes, plaintext, sessionId);
  }
  return std::make_tuple(comparisonRes, plaintext, sessionId);
}
/******************************************************************************/
