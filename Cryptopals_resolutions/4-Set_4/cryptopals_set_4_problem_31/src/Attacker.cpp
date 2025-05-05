#include <cpr/cpr.h>
#include "crow.h"
#include <iostream>

#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(bool debugFlag)
    : _debugFlag{debugFlag} {
    }
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method will try to break HMAC SHA1 signature for any given 
 * file.
 * 
 * This method will try to break HMAC SHA1 signature for any given 
 * file, the signature will be validated on the server side.
 */
void Attacker::breakHmacSHA1() {
  std::string fileName = "foo";
  std::string signature = "46b4ec586117154dacd49d664e5d63fdc88efb51";
  cpr::Response response = cpr::Get(
    cpr::Url{std::string("http://localhost:") + std::to_string(_portServerProduction) + std::string("/test")},
    cpr::Parameters{{"file", fileName}, {"signature", signature}});
  std::cout << "Status Code: " << response.status_code << "\n";
  std::cout << "Headers:\n";
  for (const auto& header : response.header) {
      std::cout << header.first << ": " << header.second << "\n";
  }
  std::cout << "Body:\n" << response.text << "\n";
}
/******************************************************************************/