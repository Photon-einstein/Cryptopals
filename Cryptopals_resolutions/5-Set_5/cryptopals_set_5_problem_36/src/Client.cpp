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

bool Client::_isServerFlag = false;

/* constructor / destructor */

/**
 * @brief This method will execute the constructor of the Client object.
 *
 * This method will perform the constructor of the Client object when a group
 * name is used in its constructor.
 *
 * @param clientId The client id to be used by this client.
 * @param debugFlag The boolean flag to decide if aggressive prints should be
 * displayed into the standard output, created for troubleshooting purposes.
 *
 * @throw runtime_error if clientId is empty.
 */
Client::Client(const std::string &clientId, const bool debugFlag)
    : _clientId{clientId}, _debugFlag{debugFlag},
      _minSaltSizesMap{EncryptionUtility::getMinSaltSizes()},
      _hashMap{EncryptionUtility::getHashMap()} {
  if (_clientId.size() == 0) {
    throw std::runtime_error("Client log | constructor(): "
                             "Client ID is null.");
  }
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
/**
 * @brief This method sets the server's production port to a new one.
 *
 * This method sets the server's production port to a new one.
 *
 * @param portServerTest The port number to be used in production.
 *
 * @throw runtime_error if the portProduction is not a valid one.
 */
void Client::setProductionPort(const int portServerProduction) {
  if (portServerProduction < 1024 || portServerProduction > 49151) {
    throw std::runtime_error("Client log | setProductionPort(): "
                             "invalid production port number given, must be in "
                             "range [1024, 49151].");
  }
  _portServerProduction = portServerProduction;
}
/******************************************************************************/
/**
 * @brief This method sets the server's test port to a new one.
 *
 * This method sets the server's test port to a new one, used only for
 * test purposes.
 *
 * @param portServerTest The port number to be used in the test scenario.
 *
 * @throw runtime_error if the portServerTest is not a valid one.
 */
void Client::setTestPort(const int portServerTest) {
  if (portServerTest < 1024 || portServerTest > 49151) {
    throw std::runtime_error(
        "Client log | setTestPort(): "
        "invalid port test number given, must be in range [1024, 49151].");
  }
  _portServerTest = portServerTest;
}
/******************************************************************************/
/**
 * @brief This method return the client ID.
 *
 * This method return the client ID of a given client.
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
 * @brief This method will return the production port of the server.
 *
 * @return The production port of the server to establish a connection.
 */
const int Client::getProductionPort() const { return _portServerProduction; }
/******************************************************************************/
/**
 * @brief This method will return the test port of the server.
 *
 * @return The test port of the server to establish a connection.
 */
const int Client::getTestPort() const { return _portServerTest; }
/******************************************************************************/
/**
 * @brief This method returns the location of the file where the public
 * configurations of the Secure Remote Password protocol are available.
 *
 * @return Filename where the public configurations of the Secure Remote
 * Password protocol are available.
 */
const std::string &Client::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getSrpParametersFilenameLocation(): public SRP "
                             "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
/******************************************************************************/
/**
 * @brief This method will perform the registration step with a given
 * server.
 *
 * This method perform the registration step with a given server.
 * It will propose a certain group ID that can be accepted or rejected
 * by the server, in the latter case it would be overwritten during this
 * step.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 * @param groupId The group ID that the client is proposing to the client.
 *
 * @return True if the registration succeed, false otherwise.
 */
const bool Client::registration(const int portServerNumber,
                                const unsigned int groupId) {
  bool registrationResult{true};
  try {
    if (portServerNumber < 1023 || (portServerNumber != _portServerProduction &&
                                    portServerNumber != _portServerTest)) {
      throw std::runtime_error("Client log | registration(): "
                               "Invalid port server number used.");
    }
    registrationResult = registrationInit(portServerNumber, groupId);
    if (!registrationResult) {
      return registrationResult;
    }
    return registrationComplete(portServerNumber, _sessionData->_groupId);
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    registrationResult = false;
    return registrationResult;
  } catch (...) {
    std::cerr << "Client log | Unknown exception caught" << std::endl;
    registrationResult = false;
    return registrationResult;
  }
}
/******************************************************************************/
/**
 * @brief This method will perform the authentication step with a given
 * server.
 *
 * This method perform the authentication step with a given server.
 * It is assumed that the registration was already completed at a previous
 * time.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 *
 * @return True if the authentication succeed, false otherwise.
 */
const bool Client::authentication(const int portServerNumber) {
  bool registrationResult{true};
  try {
    if (portServerNumber < 1023 || (portServerNumber != _portServerProduction &&
                                    portServerNumber != _portServerTest)) {
      throw std::runtime_error("Client log | authentication(): "
                               "Invalid port server number used.");
    }
    // check if the registration was already done
    if (!_sessionData->registrationComplete) {
      throw std::runtime_error("Client log | authentication(): "
                               "Registration is not completed.");
    }
    registrationResult = authenticationInit(portServerNumber);
    if (!registrationResult) {
      return registrationResult;
    }
    return true;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    registrationResult = false;
    return registrationResult;
  } catch (...) {
    std::cerr << "Client log | Unknown exception caught" << std::endl;
    registrationResult = false;
    return registrationResult;
  }
}
/******************************************************************************/
/**
 * @brief Returns whether this class is acting as a server.
 * @return True if this is a server, false otherwise.
 */
bool Client::getIsServerFlag() { return _isServerFlag; }
/******************************************************************************/
/**
 * @brief This method will perform the first step of the registration
 * with a given server.
 *
 * This method perform the first step of the registration with a given
 * server. It will propose a certain group ID that can be accepted
 * or rejected by the server, in the latter case it would be overwritten
 * during this step.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 * @param groupId The group ID of this session.
 *
 * @return True if the registrationInit succeed, false otherwise.
 */
const bool Client::registrationInit(const int portServerNumber,
                                    const unsigned int groupId) {
  bool registrationInitResult{true};
  try {
    std::string requestBody = fmt::format(
        R"({{
        "clientId": "{}",
        "requestedGroup": "{}"
    }})",
        getClientId(), groupId);
    cpr::Response response =
        cpr::Post(cpr::Url{std::string("http://localhost:") +
                           std::to_string(portServerNumber) +
                           std::string("/srp/register/init")},
                  cpr::Header{{"Content-Type", "application/json"}},
                  cpr::Body{requestBody});
    if (_debugFlag) {
      printServerResponse(response);
    }
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "registration failed");
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    const std::string extractedClientId =
        parsedJson.at("clientId").get<std::string>();
    const unsigned int extractedGroupId =
        parsedJson.at("groupId").get<unsigned int>();
    const std::string extractedGroupName =
        parsedJson.at("groupName").get<std::string>();
    const std::string extractedPrimeN =
        parsedJson.at("primeN").get<std::string>();
    const unsigned int extractedGeneratorG =
        parsedJson.at("generatorG").get<unsigned int>();
    const std::string extractedSalt = parsedJson.at("salt").get<std::string>();
    const std::string extractedSha = parsedJson.at("sha").get<std::string>();
    if (_debugFlag) {
      std::cout << "\n--- Client log | /srp/register/init server response "
                   "extracted data ---"
                << std::endl;
      std::cout << "\tClient ID: " << extractedClientId << std::endl;
      std::cout << "\tGroup ID: " << extractedGroupId << std::endl;
      std::cout << "\tGroup name: " << extractedGroupName << std::endl;
      std::cout << "\tPrime N: " << extractedPrimeN << std::endl;
      std::cout << "\tGenerator g: " << extractedGeneratorG << std::endl;
      std::cout << "\tSalt: " << extractedSalt << std::endl;
      std::cout << "\tSHA: " << extractedSha << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    // Client side server response validation
    const unsigned int minSaltSize =
        _minSaltSizesMap.at(_srpParametersMap.at(extractedGroupId)._hashName);
    if (extractedClientId != getClientId()) {
      throw std::runtime_error(
          "Client log | registrationInit(): "
          "Client ID received does not match's client's one.");
    } else if (_srpParametersMap.find(extractedGroupId) ==
               _srpParametersMap.end()) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "Group ID received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._nHex !=
               extractedPrimeN) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "Prime N received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._g !=
               extractedGeneratorG) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "Generator g received not valid.");
    } else if (_srpParametersMap.at(extractedGroupId)._hashName !=
               extractedSha) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "Hash name received not valid.");
    } else if (extractedSalt.size() < minSaltSize * 2) { /* salt is in hex */
      throw std::runtime_error("Client log | registrationInit(): "
                               "Minimum salt size is not met.");
    }
    // Data storage
    _sessionData = std::make_unique<SessionData>(
        extractedGroupId, extractedSalt, extractedSha, _debugFlag);
    if (_sessionData.get() == nullptr) {
      throw std::runtime_error("Client log | registrationInit(): "
                               "_sessionData value returned is null.");
    }
    return registrationInitResult;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    registrationInitResult = false;
    return registrationInitResult;
  } catch (...) {
    std::cerr << "Client log | Unknown exception caught" << std::endl;
    registrationInitResult = false;
    return registrationInitResult;
  }
}
/******************************************************************************/
/**
 * @brief This method will perform the last step of the registration
 * with a given server.
 *
 * This method perform the last step of the registration step with a
 * given server. It will perform the computation of x and v and then
 * send to the server U and v.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 * @param groupId The group ID of this session.
 *
 * @return True if the registrationComplete succeed, false otherwise.
 */
const bool Client::registrationComplete(const int portServerNumber,
                                        const unsigned int groupId) {
  bool registrationCompleteResult{true};
  try {
    if (_sessionData.get() == nullptr) {
      throw std::runtime_error("Client log | registrationComplete(): "
                               "_sessionData value is null.");
    }
    _sessionData->_password =
        EncryptionUtility::generatePassword(_passwordSize);
    if (_sessionData->_password.size() < _passwordSize) {
      throw std::runtime_error("Client log | registrationComplete(): "
                               "generatePassword() failed.");
    }
    if (_debugFlag) {
      std::cout << "Password generated: '" << _sessionData->_password << "'."
                << std::endl;
    }
    // x calc
    const std::string xHex = calculateX(
        _sessionData->_hash, _sessionData->_password, _sessionData->_salt);
    if (_debugFlag) {
      std::cout << "x(hex) = H(s | P): '" << xHex << "'." << std::endl;
    }
    // v calc
    std::string vHex = calculateV(xHex, _srpParametersMap.at(groupId)._nHex,
                                  _srpParametersMap.at(groupId)._g);
    if (_debugFlag) {
      std::cout << "v(hex) = g^x mod N ='" << vHex << "'." << std::endl;
    }
    std::string requestBody = fmt::format(
        R"({{
        "clientId": "{}",
        "v": "{}"
    }})",
        getClientId(), vHex);
    cpr::Response response =
        cpr::Post(cpr::Url{std::string("http://localhost:") +
                           std::to_string(portServerNumber) +
                           std::string("/srp/register/complete")},
                  cpr::Header{{"Content-Type", "application/json"}},
                  cpr::Body{requestBody});
    if (_debugFlag) {
      printServerResponse(response);
    }
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | registrationComplete(): "
                               "registration failed");
    }
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    const std::string extractedServerConfirmation =
        parsedJson.at("confirmation").get<std::string>();
    if (_debugFlag) {
      std::cout << "\n--- Client log | /srp/register/complete server response "
                   "extracted data ---"
                << std::endl;
      std::cout << "\tServer confirmation: " << extractedServerConfirmation
                << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    if (_serverConfirmationMessage != _serverConfirmationMessage) {
      throw std::runtime_error(
          "Client log | registrationComplete(): "
          "extracted server confirmation don't match, expected: '" +
          _serverConfirmationMessage + "', actual: '" +
          _serverConfirmationMessage + "'.");
    }
    // mark the registration step as complete at this point
    _sessionData->registrationComplete = true;
    return registrationCompleteResult;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    registrationCompleteResult = false;
    return registrationCompleteResult;
  } catch (...) {
    std::cerr << "Client log | Unknown exception caught" << std::endl;
    registrationCompleteResult = false;
    return registrationCompleteResult;
  }
}
/******************************************************************************/
/**
 * @brief This method will perform the first step of the authentication
 * with a given server.
 *
 * This method perform the first step of the authentication with a given
 * server. It will perform the calculations and verifications involved
 * at the first leg of the authentication of SRP protocol.
 *
 * @param portServerNumber The number of the server to use in this exchange.
 *
 * @return True if the authenticationInit succeed, false otherwise.
 */
const bool Client::authenticationInit(const int portServerNumber) {
  bool authenticationInitResult{true};
  try {
    std::string requestBody = fmt::format(
        R"({{
        "clientId": "{}"
    }})",
        getClientId());
    cpr::Response response =
        cpr::Post(cpr::Url{std::string("http://localhost:") +
                           std::to_string(portServerNumber) +
                           std::string("/srp/auth/init")},
                  cpr::Header{{"Content-Type", "application/json"}},
                  cpr::Body{requestBody});
    if (_debugFlag) {
      printServerResponse(response);
    }
    if (response.status_code != 201) {
      throw std::runtime_error("Client log | authenticationInit(): "
                               "authentication failed");
    }
    // Reception of s, B and group ID from the server
    nlohmann::json parsedJson = nlohmann::json::parse(response.text);
    const std::string extractedClientId =
        parsedJson.at("clientId").get<std::string>();
    const std::string extractedSaltHex =
        parsedJson.at("salt").get<std::string>();
    const std::string extractedBHex = parsedJson.at("B").get<std::string>();
    const unsigned int extractedGroupId =
        parsedJson.at("groupId").get<unsigned int>();
    // Validation of s, B and group ID from the server
    if (extractedClientId != _clientId) {
      throw std::runtime_error(
          "Client log | authenticationInit(): "
          "extracted cliend ID doesn't match at the client's side.");
    } else if (extractedSaltHex != _sessionData->_salt) {
      throw std::runtime_error(
          "Client log | authenticationInit(): "
          "extracted salt doesn't match at the client's side.");
    } else if (extractedGroupId != _sessionData->_groupId) {
      throw std::runtime_error(
          "Client log | authenticationInit(): "
          "Group ID received from the server doesn't match session's one.");
    } else if (!MyCryptoLibrary::SecureRemotePassword::validatePublicKey(
                   extractedBHex, _srpParametersMap[extractedGroupId]._nHex)) {
      throw std::runtime_error("Client log | authenticationInit(): "
                               "Server public key failed the verification.");
    }
    // store of B server's public key
    _sessionData->_peerPublicKeyHex = extractedBHex;
    // private key generation
    const unsigned int minPrivateKeyBits =
        _sessionData->_secureRemotePassword->getMinSizePrivateKey();
    _sessionData->_privateKeyHex =
        MyCryptoLibrary::SecureRemotePassword::generatePrivateKey(
            _srpParametersMap.at(extractedGroupId)._nHex, minPrivateKeyBits);
    if (_debugFlag) {
      std::cout << "\n--- Client log | Private key generated at the "
                   "authentication phase---"
                << std::endl;
      std::cout << "\tClient ID: " << extractedClientId << std::endl;
      std::cout << "\tPrivate key: " << _sessionData->_privateKeyHex
                << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    // public key generation
    _sessionData->_publicKeyHex =
        MyCryptoLibrary::SecureRemotePassword::calculatePublicKey(
            _sessionData->_privateKeyHex,
            _srpParametersMap.at(extractedGroupId)._nHex,
            MessageExtractionFacility::uintToHex(
                _srpParametersMap[extractedGroupId]._g),
            Client::getIsServerFlag());
    if (_debugFlag) {
      std::cout << "\n--- Client log | Public key generated at the "
                   "authentication phase---"
                << std::endl;
      std::cout << "\tClient ID: " << extractedClientId << std::endl;
      std::cout << "\tPublic key: " << _sessionData->_privateKeyHex
                << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    // u calculation
    _sessionData->_u = MyCryptoLibrary::SecureRemotePassword::calculateU(
        _srpParametersMap.at(extractedGroupId)._hashName,
        _sessionData->_publicKeyHex, _sessionData->_peerPublicKeyHex);
    if (_debugFlag) {
      std::cout << "\n--- Client log | Scrambling parameter u generated at the "
                   "authentication phase---"
                << std::endl;
      std::cout << "\tClient ID: " << extractedClientId << std::endl;
      std::cout << "\tu = H(A | B): " << _sessionData->_u << std::endl;
      std::cout << "----------------------" << std::endl;
    }
    return authenticationInitResult;
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    authenticationInitResult = false;
    return authenticationInitResult;
  } catch (...) {
    std::cerr << "Client log | Unknown exception caught" << std::endl;
    authenticationInitResult = false;
    return authenticationInitResult;
  }
}
/******************************************************************************/
/**
 * @brief This method will print the server response during the Secure Remote
 * Password protocol.
 *
 * This method will print the server response to the Secure Remote
 * Password protocol. The response is a json text, and it will be printed in a
 * structured way.
 *
 * @param response The response sent by the server during the execution
 * of the Secure Remote Password protocol.
 */
void Client::printServerResponse(const cpr::Response &response) {
  std::cout << "Status Code: " << response.status_code << std::endl;
  std::cout << "Headers:\n";
  for (const auto &header : response.header) {
    std::cout << header.first << ": " << header.second << std::endl;
  }
  std::cout << "Body:\n";
  if (response.text.empty()) {
    std::cout << "[Empty Body]\n";
  } else {
    try {
      nlohmann::json parsedJson = nlohmann::json::parse(response.text);
      std::cout << parsedJson.dump(2)
                << std::endl; // '2' for 2-space indentation
    } catch (const nlohmann::json::exception &e) {
      // Not valid JSON, print as raw text
      std::cout << response.text << std::endl;
      std::cerr << "Warning: Body is not valid JSON, printing raw. Error: "
                << e.what() << std::endl;
    } catch (...) {
      // Not valid JSON, print as raw text
      std::cout << response.text << std::endl;
      std::cerr << "Client log | Unknown exception caught" << std::endl;
    }
  }
}
/******************************************************************************/
/**
 * @brief This method will perform the following calculation:
 * x = H(s | P).
 *
 * This method will perform the following calculation:
 * x = H(s | P).
 * Clarification:
 * - H: hash algorithm;
 * - s: salt;
 * - P: password;
 * - x: output of the hash;
 *
 * @param hash The hash algorithm used in this calculation.
 * @param password The password used in this calculation, received in plaintext.
 * @param salt The salt used in this calculation, received in hexadecimal format
 *
 * @return The result of H(s | P) in hexadecimal format.
 */
const std::string Client::calculateX(const std::string &hash,
                                     const std::string &password,
                                     const std::string &salt) {
  if (_hashMap.find(hash) == _hashMap.end()) {
    throw std::runtime_error("Client log | calculateX(): "
                             "hash algorithm not recognized.");
  }
  const std::string saltPlaintext =
      MessageExtractionFacility::hexToPlaintext(salt);
  const std::string digestX = _hashMap.at(hash)(saltPlaintext + password);
  return digestX;
}
/******************************************************************************/
/**
 * @brief This method will perform the calculation v = g^x mod N.
 *
 * @param xHex The value of x, as a hexadecimal string.
 * @param nHex The value of the large prime N, as a hexadecimal string.
 * @param g The value of the generator g.
 *
 * @return The result of v = g^x mod N, in hexadecimal format.
 * @throw std::runtime_error If the calculation fails.
 */
const std::string Client::calculateV(const std::string &xHex,
                                     const std::string &nHex, unsigned int g) {
  // Allocate with RAII
  EncryptionUtility::BnCtxPtr ctx(BN_CTX_new());
  if (!ctx) {
    throw std::runtime_error(
        "Client log | calculateV(): Failed to allocate BN_CTX.");
  }
  EncryptionUtility::BnPtr gBn(BN_new());
  EncryptionUtility::BnPtr vBn(BN_new());
  if (!gBn || !vBn) {
    throw std::runtime_error(
        "Client log | calculateV(): Failed to allocate BIGNUMs.");
  }
  BIGNUM *xBn = nullptr;
  BIGNUM *nBn = nullptr;
  if (!BN_hex2bn(&xBn, xHex.c_str()) || !BN_hex2bn(&nBn, nHex.c_str())) {
    BN_free(xBn);
    BN_free(nBn);
    throw std::runtime_error(
        "Client log | calculateV(): Failed to convert hex strings to BIGNUM.");
  }
  // Wrap xBn and nBn now that they're allocated
  EncryptionUtility::BnPtr xPtr(xBn);
  EncryptionUtility::BnPtr nPtr(nBn);
  BN_set_word(gBn.get(), g);
  // Compute v = g^x mod N
  if (!BN_mod_exp(vBn.get(), gBn.get(), xPtr.get(), nPtr.get(), ctx.get())) {
    throw std::runtime_error("Client log | calculateV(): BN_mod_exp failed.");
  }
  // Convert result to hex string
  EncryptionUtility::OsslStr vHex(BN_bn2hex(vBn.get()));
  if (!vHex) {
    throw std::runtime_error(
        "Client log | calculateV(): Failed to convert result to hex.");
  }
  return std::string(vHex.get()); // safely copy to std::string
}
/******************************************************************************/
