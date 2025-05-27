#include "crow.h"
#include <chrono>
#include <iostream>

#include "./../include/Client.hpp"

/* constructor / destructor */
Client::Client()
    : _diffieHellman(std::make_unique<MyCryptoLibrary::Diffie_Hellman>()) {}
/******************************************************************************/
Client::~Client() {}
/******************************************************************************/