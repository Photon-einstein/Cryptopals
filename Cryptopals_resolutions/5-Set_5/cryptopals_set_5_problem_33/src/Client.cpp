#include "crow.h"
#include <chrono>
#include <iostream>
#include <openssl/rand.h>

#include "./../include/Client.hpp"

/* constructor / destructor */
Client::Client()
    : _diffieHellman(std::make_unique<MyCryptoLibrary::Diffie_Hellman>()) {
  _clientNonceHex =
      MessageExtractionFacility::generateCryptographicNonce(_nonceSize);
  std::cout << "Client log | Nonce (hex): " << _clientNonceHex << std::endl;
}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/
