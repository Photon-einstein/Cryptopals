#include "crow.h"
#include <chrono>
#include <iostream>

#include "./../include/Client.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Client::Client() {
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
  }
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/