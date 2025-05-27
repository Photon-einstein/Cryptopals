#include "crow.h"
#include <chrono>
#include <iostream>

#include "./../include/Client.hpp"

/* constructor / destructor */
Client::Client() {
  std::map<std::string, DHParametersLoader::DHParameters> dhParametersMap =
      DHParametersLoader::loadDhParameters(_dhParametersFilename);
  if (dhParametersMap.find("cryptopals-group-33-small") !=
      dhParametersMap.end()) {
    _dhParameter = dhParametersMap["cryptopals-group-33-small"];
    _p = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter.pHex);
    _g = MessageExtractionFacility::hexToUniqueBIGNUM(_dhParameter.gHex);
    std::cout << "p (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_p.get()) << std::endl;
    std::cout << "g (decimal) = "
              << MessageExtractionFacility::BIGNUMToDec(_g.get()) << std::endl;
  }
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/