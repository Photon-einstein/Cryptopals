#include "crow.h"
#include <chrono>
#include <iostream>

#include "./../include/Attacker.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Attacker::Attacker(bool debugFlag) : _debugFlag{debugFlag} {}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method will try to break HMAC SHA1 signature for any given
 * file.
 *
 * This method will try to break HMAC SHA1 signature for any given
 * file, the signature will be validated on the server side.
 *
 * @param fileName the file that the attacker is trying to find the signature
 *
 * @return bool: true if the attack succeed or false otherwise
 * @return string: the signature cracked in case the attack succeed
 */
std::tuple<bool, std::string>
Attacker::breakHmacSHA1(const std::string &fileName) {
  const std::size_t sizeBytesHmacSHA1{20};
  const std::size_t sizeByte{256};
  std::tuple<bool, cpr::Response> serverResponse;
  std::vector<unsigned char> signatureV(sizeBytesHmacSHA1, 0);
  std::string signature;
  for (std::size_t i = 0; i < sizeBytesHmacSHA1; ++i) {
    unsigned char byteGuess = 0;
    std::chrono::microseconds longestTime{0};
    for (std::size_t j = 0; j < sizeByte; ++j) {
      std::chrono::microseconds timeAverage{0};
      for (std::size_t k = 0; k < _attackSamples; ++k) {
        signatureV[i] = j;
        signature = MessageExtractionFacility::toHexString(signatureV);
        auto start = std::chrono::high_resolution_clock::now();
        serverResponse = Attacker::sendRequest(signature, fileName);
        auto end = std::chrono::high_resolution_clock::now();
        auto time =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        timeAverage += time;
      }
      timeAverage /= _attackSamples;
      if (timeAverage > longestTime) {
        longestTime = timeAverage;
        byteGuess = j;
      }
    }
    // update signature at index i with the best guess
    signatureV[i] = byteGuess;
  }
  // send to the server the signature able to be constructed with the timing
  // leak
  signature = MessageExtractionFacility::toHexString(signatureV);
  auto finalServerResponse = Attacker::sendRequest(signature, fileName);
  Attacker::printServerResponse(std::get<cpr::Response>(finalServerResponse));
  return std::make_tuple(std::get<bool>(finalServerResponse), signature);
}
/******************************************************************************/
/**
 * @brief This method will send a request to the server to validate.
 *
 * This method will send a request to the server to validate. It will send the
 * file to access and the signature to grant the access.
 *
 * @return bool value, true if the request response of the server is a 200
 * code success, false otherwise
 * @return cpr::Response curl response from the server
 */
std::tuple<bool, cpr::Response>
Attacker::sendRequest(const std::string &signature,
                      const std::string &fileName) {
  bool retBool;
  cpr::Response response = cpr::Get(
      cpr::Url{std::string("http://localhost:") +
               std::to_string(_portServerProduction) + std::string("/test")},
      cpr::Parameters{{"file", fileName}, {"signature", signature}});
  if (response.status_code == 200) {
    return std::make_tuple(true, response);
  }
  return std::make_tuple(false, response);
}
/******************************************************************************/
/**
 * @brief This method will print in a structured way the server response
 *
 * This method will print in a structured way the server response to an attacker
 * curl request.
 */
void Attacker::printServerResponse(const cpr::Response &response) {
  std::cout << "Status Code: " << response.status_code << "\n";
  std::cout << "Headers:\n";
  for (const auto &header : response.header) {
    std::cout << header.first << ": " << header.second << "\n";
  }
  std::cout << "Body:\n" << response.text << "\n";
}
/******************************************************************************/
