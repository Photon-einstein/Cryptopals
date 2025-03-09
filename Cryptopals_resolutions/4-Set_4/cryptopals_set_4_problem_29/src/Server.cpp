#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <stdexcept>

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag)
    : _debugFlag(debugFlag), _sha(std::make_shared<MyCryptoLibrary::SHA1>()) {}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
